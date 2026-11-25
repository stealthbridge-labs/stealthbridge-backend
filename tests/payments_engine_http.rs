//! Payment-engine reliability over real HTTP + PostgreSQL, against a mock
//! Stellar RPC whose behaviour each scenario controls: ambiguous and
//! rejected broadcasts, never-included transactions, receipts that don't
//! match, and concurrent submissions competing for the relayer sequence.
use axum::{extract::State, routing::post, serve, Json, Router};
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use stealthbridge_backend::{
    relayer,
    server::{router, AppState},
    smart_account_payments as pay,
};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, ContractEvent, ContractEventBody, ContractEventType,
    ContractEventV0, ContractId, ExtensionPoint, Hash, HostFunction, LedgerEntryData,
    LedgerFootprint, Limits, OperationBody, PublicKey, ReadXdr, ScVal, SequenceNumber,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, String32, Thresholds, TransactionEnvelope, Uint256, WriteXdr,
};
use uuid::Uuid;

const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
const SECRET: &[u8] = b"isolated-ci-payments-engine-bridge-secret-32b";
const DOMAIN: &str = "stealthbridge-smart-account-payments-v1";
const PATH: &str = "/v1/account/smart-accounts/payments";
const ACCOUNT: &str = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";
const DEST: &str = "GBXXE7JVT6JPUOLBYZM4ECD63DUVGGPJZXYMVVLUZT42GFPHXG3UEARH";
const RP: &str = "stealthbridge.vercel.app";
static NONCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1_000);

#[derive(Clone, Copy, PartialEq)]
enum SendMode {
    Accept,
    Error,
    Transport, // HTTP 500: the relayer cannot tell whether it was queued
}

#[derive(Default)]
struct Mock {
    seq: i64,
    send_mode: Option<SendMode>,
    sent: Vec<(String, i64)>, // (envelope b64, sequence)
    /// tx hash -> "SUCCESS" | "FAILED" with the amount the event will show
    outcomes: std::collections::HashMap<String, (&'static str, i64)>,
}

type Shared = Arc<Mutex<Mock>>;

fn b64d(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.bytes().filter(|b| *b != b'=') {
        acc = (acc << 6) | T.iter().position(|x| *x == b).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn tx_data() -> String {
    let d = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: vec![].try_into().unwrap(),
                read_write: vec![].try_into().unwrap(),
            },
            instructions: 1,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 5_000,
    };
    relayer::b64(&d.to_xdr(Limits::none()).unwrap())
}

fn transfer_event(token: [u8; 32], from: &ScVal, to: &ScVal, amount: i64) -> String {
    let ev = ContractEvent {
        ext: ExtensionPoint::V0,
        contract_id: Some(ContractId(Hash(token))),
        type_: ContractEventType::Contract,
        body: ContractEventBody::V0(ContractEventV0 {
            topics: vec![
                ScVal::Symbol("transfer".try_into().unwrap()),
                from.clone(),
                to.clone(),
                ScVal::Void,
            ]
            .try_into()
            .unwrap(),
            data: ScVal::I128(stellar_xdr::Int128Parts {
                hi: 0,
                lo: amount as u64,
            }),
        }),
    };
    relayer::b64(&ev.to_xdr(Limits::none()).unwrap())
}

async fn rpc(State(m): State<Shared>, Json(req): Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = req["method"].as_str().unwrap_or("");
    let p = &req["params"];
    let ok = |r: Value| Json(json!({"jsonrpc":"2.0","id":req["id"],"result":r})).into_response();
    match method {
        "getNetwork" => ok(json!({"passphrase": relayer::TESTNET_PASSPHRASE})),
        "getLatestLedger" => ok(json!({"sequence": 1000})),
        "getLedgerEntries" => {
            let seq = m.lock().unwrap().seq;
            let entry = LedgerEntryData::Account(AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1; 32]))),
                balance: 1_000_000_000,
                seq_num: SequenceNumber(seq),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: vec![].try_into().unwrap(),
                ext: AccountEntryExt::V0,
            });
            ok(
                json!({"entries":[{"xdr": relayer::b64(&entry.to_xdr(Limits::none()).unwrap())}],"latestLedger":1000}),
            )
        }
        "simulateTransaction" => {
            let env = TransactionEnvelope::from_xdr(
                b64d(p["transaction"].as_str().unwrap()),
                Limits::none(),
            )
            .unwrap();
            let TransactionEnvelope::Tx(v1) = env else {
                unreachable!()
            };
            let OperationBody::InvokeHostFunction(f) = &v1.tx.operations[0].body else {
                unreachable!()
            };
            let HostFunction::InvokeContract(call) = &f.host_function else {
                unreachable!()
            };
            if call.function_name.0.as_slice() == b"balance" {
                return ok(
                    json!({"results":[{"xdr": relayer::b64(&ScVal::I128(stellar_xdr::Int128Parts{hi:0,lo:5_000_000_000}).to_xdr(Limits::none()).unwrap())}],"transactionData":tx_data(),"minResourceFee":"5000"}),
                );
            }
            let auth: Vec<String> = if f.auth.is_empty() {
                let e = SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                        address: stellar_xdr::ScAddress::Contract(ContractId(Hash(
                            relayer::contract_hash(ACCOUNT).unwrap(),
                        ))),
                        nonce: NONCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        signature_expiration_ledger: 0,
                        signature: ScVal::Void,
                    }),
                    root_invocation: SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                        sub_invocations: vec![].try_into().unwrap(),
                    },
                };
                vec![relayer::b64(&e.to_xdr(Limits::none()).unwrap())]
            } else {
                // Enforcing mode: the real contract would verify here.
                vec![]
            };
            ok(
                json!({"results":[{"auth":auth,"xdr":"AAAAAQ=="}],"transactionData":tx_data(),"minResourceFee":"5000"}),
            )
        }
        "sendTransaction" => {
            let mut g = m.lock().unwrap();
            let env_b64 = p["transaction"].as_str().unwrap().to_owned();
            let env = TransactionEnvelope::from_xdr(b64d(&env_b64), Limits::none()).unwrap();
            let TransactionEnvelope::Tx(v1) = env else {
                unreachable!()
            };
            let seq = v1.tx.seq_num.0;
            g.sent.push((env_b64, seq));
            match g.send_mode.unwrap_or(SendMode::Accept) {
                SendMode::Accept => {
                    // The relayer account's sequence advances on acceptance.
                    g.seq = seq;
                    ok(json!({"status":"PENDING"}))
                }
                SendMode::Error => ok(json!({"status":"ERROR","errorResultXdr":"AAAA"})),
                SendMode::Transport => {
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                }
            }
        }
        "getTransaction" => {
            let g = m.lock().unwrap();
            let hash = p["hash"].as_str().unwrap();
            let Some((status, event_amount)) = g.outcomes.get(hash).copied() else {
                return ok(json!({"status":"NOT_FOUND","latestLedger":1000}));
            };
            // Find the envelope we were sent with this hash.
            let env = g.sent.iter().map(|(e, _)| e.clone()).find(|e| {
                let env = TransactionEnvelope::from_xdr(b64d(e), Limits::none()).unwrap();
                let TransactionEnvelope::Tx(v1) = env else {
                    return false;
                };
                relayer::transaction_hash(&v1.tx, relayer::TESTNET_PASSPHRASE) == hash
            });
            let token = pay::PayAsset::parse("XLM")
                .unwrap()
                .contract_id(relayer::TESTNET_PASSPHRASE)
                .unwrap();
            let ev = transfer_event(
                token,
                &pay::address_scval(ACCOUNT).unwrap(),
                &pay::address_scval(DEST).unwrap(),
                event_amount,
            );
            ok(
                json!({"status":status,"txHash":hash,"ledger":1001,"latestLedger":1001,"createdAt":"1795600000",
                "envelopeXdr":env,"events":{"contractEventsXdr":[[ev]],"transactionEventsXdr":[]}}),
            )
        }
        _ => ok(json!({})),
    }
}

fn signed(c: &reqwest::Client, base: &str, method: &str, body: &str) -> reqwest::RequestBuilder {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let (nonce, digest) = if method == "GET" {
        (String::new(), String::new())
    } else {
        (
            Uuid::new_v4().to_string(),
            hex::encode(Sha256::digest(body.as_bytes())),
        )
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(
        format!("{DOMAIN}\n{method}\n{PATH}\n{OWNER}\n{stamp}\n{nonce}\n{digest}\n").as_bytes(),
    );
    c.request(method.parse().unwrap(), format!("{base}{PATH}"))
        .header("x-stealthbridge-account", OWNER)
        .header("x-stealthbridge-issued-at", stamp)
        .header("x-stealthbridge-nonce", nonce)
        .header(
            "x-stealthbridge-signature",
            hex::encode(mac.finalize().into_bytes()),
        )
        .header("content-type", "application/json")
        .body(body.to_owned())
}

fn assertion(key: &SigningKey, challenge: &str) -> Value {
    let mut ad = relayer::rp_id_hash(RP).to_vec();
    ad.push(0x05);
    ad.extend_from_slice(&1u32.to_be_bytes());
    let cd = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{RP}","crossOrigin":false}}"#).into_bytes();
    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&cd));
    let digest: [u8; 32] = Sha256::digest(&signed).into();
    let sig: Signature = key.sign_prehash(&digest).unwrap();
    json!({"authenticator_data": pay::b64url(&ad), "client_data_json": pay::b64url(&cd), "signature": pay::b64url(sig.to_der().as_bytes())})
}

struct Harness {
    base: String,
    db: PgPool,
    key: SigningKey,
    c: reqwest::Client,
}

impl Harness {
    async fn prepare(&self, amount: i64) -> Value {
        let body = json!({"action":"prepare","contract_address":ACCOUNT,"destination":DEST,"asset":"XLM","amount_stroops":amount}).to_string();
        let res = signed(&self.c, &self.base, "POST", &body)
            .send()
            .await
            .unwrap();
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        assert_eq!(status, 201, "{v}");
        v
    }
    async fn submit(&self, intent: &Value) -> (u16, Value) {
        let mut a = assertion(&self.key, intent["challenge"].as_str().unwrap());
        a["action"] = json!("submit");
        a["id"] = intent["id"].clone();
        let res = signed(&self.c, &self.base, "POST", &a.to_string())
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }
    async fn row(&self, id: &str) -> (String, Option<String>, Option<String>) {
        sqlx::query_as(
            "SELECT status, tx_hash, error_code FROM account_smart_account_payments WHERE id=$1",
        )
        .bind(Uuid::parse_str(id).unwrap())
        .fetch_one(&self.db)
        .await
        .unwrap()
    }
    async fn list(&self) -> Value {
        signed(&self.c, &self.base, "GET", "")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn payment_engine_is_safe_under_ambiguity_rejection_mismatch_and_concurrency() {
    // ---- mock RPC
    let mock: Shared = Arc::new(Mutex::new(Mock {
        seq: 100,
        ..Default::default()
    }));
    let rpc_app = Router::new()
        .route("/rpc", post(rpc))
        .with_state(mock.clone());
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}/rpc", rpc_listener.local_addr().unwrap());
    tokio::spawn(async move { serve(rpc_listener, rpc_app).await.unwrap() });

    // ---- API
    let db = PgPool::connect(&std::env::var("DATABASE_URL").expect("isolated CI PostgreSQL"))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    std::env::set_var("STEALTHBRIDGE_ALLOW_LOCAL_NETWORK", "true");
    std::env::set_var("STELLAR_RPC_URL", &rpc_url);
    std::env::set_var(
        "STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET",
        std::str::from_utf8(SECRET).unwrap(),
    );
    std::env::set_var(
        "STEALTHBRIDGE_RELAYER_SECRET",
        stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([8; 32]))
            .to_string()
            .as_str(),
    );
    std::env::set_var(
        "STEALTHBRIDGE_RECONCILE_TOKEN",
        "test-reconcile-token-that-is-at-least-32-bytes",
    );
    let app = router(AppState::from_env().await.unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { serve(listener, app).await.unwrap() });

    // ---- a deployed passkey account owned by OWNER
    let key = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
    let pk = hex::encode(key.verifying_key().to_encoded_point(false).as_bytes());
    sqlx::query("DELETE FROM account_smart_account_payments WHERE account_address=$1")
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM account_smart_account_deployments WHERE account_address=$1")
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO account_smart_account_deployments(account_address,contract_address,label,owner_public_key,credential_id,rp_id,guardian_address,factory_address,network,tx_hash,status,ledger,created_at_unix,updated_at_unix)
        VALUES($1,$2,'Engine',$3,'EngineCredential000001',$4,NULL,$2,'testnet',$5,'deployed',10,1,1)")
        .bind(OWNER).bind(ACCOUNT).bind(&pk).bind(RP).bind("e".repeat(64)).execute(&db).await.unwrap();
    let h = Harness {
        base,
        db,
        key,
        c: reqwest::Client::new(),
    };

    // 1. Happy path: write-ahead hash == hash of the broadcast envelope,
    //    time bounds set, confirmation only after the receipt matches.
    let intent = h.prepare(25_000_000).await;
    assert!(
        intent["fee_estimate_stroops"].as_i64().unwrap() > 100_000,
        "estimate includes base fee"
    );
    let (status, body) = h.submit(&intent).await;
    assert_eq!(status, 202, "{body}");
    let hash = body["tx_hash"].as_str().unwrap().to_owned();
    {
        let g = mock.lock().unwrap();
        let (env, _) = g.sent.last().unwrap();
        let TransactionEnvelope::Tx(v1) =
            TransactionEnvelope::from_xdr(b64d(env), Limits::none()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            relayer::transaction_hash(&v1.tx, relayer::TESTNET_PASSPHRASE),
            hash
        );
        assert!(matches!(v1.tx.cond, stellar_xdr::Preconditions::Time(ref t) if t.max_time.0 > 0));
    }
    assert_eq!(h.row(intent["id"].as_str().unwrap()).await.0, "submitted");
    mock.lock()
        .unwrap()
        .outcomes
        .insert(hash.clone(), ("SUCCESS", 25_000_000));
    let l = h.list().await;
    let p = &l["payments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == intent["id"])
        .unwrap()
        .clone();
    assert_eq!(p["status"], "confirmed");
    assert_eq!(p["ledger"], 1001);

    // 2. Receipt mismatch: SUCCESS but the transfer event shows another amount.
    let intent = h.prepare(30_000_000).await;
    let (_, body) = h.submit(&intent).await;
    mock.lock().unwrap().outcomes.insert(
        body["tx_hash"].as_str().unwrap().into(),
        ("SUCCESS", 29_999_999),
    );
    h.list().await;
    let (s, _, code) = h.row(intent["id"].as_str().unwrap()).await;
    assert_eq!(
        (s.as_str(), code.as_deref()),
        ("failed", Some("EVIDENCE_MISMATCH"))
    );

    // 3. Ambiguous broadcast: never marked failed on the spot; hash persisted
    //    first; once the time bounds pass, NOT_FOUND becomes NOT_INCLUDED.
    mock.lock().unwrap().send_mode = Some(SendMode::Transport);
    let intent = h.prepare(10_000_000).await;
    let (status, body) = h.submit(&intent).await;
    assert_eq!(status, 202);
    assert_eq!(body["confirmation"], "pending");
    let id = intent["id"].as_str().unwrap().to_owned();
    let (s, tx, _) = h.row(&id).await;
    assert_eq!(s, "submitted");
    assert!(tx.is_some(), "hash written before broadcast");
    h.list().await;
    assert_eq!(
        h.row(&id).await.0,
        "submitted",
        "NOT_FOUND within time bounds is not final"
    );
    sqlx::query("UPDATE account_smart_account_payments SET updated_at_unix=updated_at_unix-1000, created_at_unix=created_at_unix-1000 WHERE id=$1")
        .bind(Uuid::parse_str(&id).unwrap()).execute(&h.db).await.unwrap();
    h.list().await;
    let (s, _, code) = h.row(&id).await;
    assert_eq!(
        (s.as_str(), code.as_deref()),
        ("failed", Some("NOT_INCLUDED"))
    );

    // 4. Definitive rejection.
    mock.lock().unwrap().send_mode = Some(SendMode::Error);
    let intent = h.prepare(11_000_000).await;
    let (status, _) = h.submit(&intent).await;
    assert_eq!(status, 502);
    let (s, _, code) = h.row(intent["id"].as_str().unwrap()).await;
    assert_eq!(
        (s.as_str(), code.as_deref()),
        ("failed", Some("SUBMISSION_REJECTED"))
    );

    // 5. Concurrency: two payments submitted at once must use distinct
    //    relayer sequence numbers (serialized by the relayer lock).
    mock.lock().unwrap().send_mode = Some(SendMode::Accept);
    let a = h.prepare(1_000_000).await;
    let b = h.prepare(2_000_000).await;
    let before = mock.lock().unwrap().sent.len();
    let (ra, rb) = tokio::join!(h.submit(&a), h.submit(&b));
    assert_eq!((ra.0, rb.0), (202, 202));
    let seqs: Vec<i64> = {
        let g = mock.lock().unwrap();
        g.sent[before..].iter().map(|(_, s)| *s).collect()
    };
    assert_eq!(seqs.len(), 2);
    assert_ne!(seqs[0], seqs[1], "sequence collision: {seqs:?}");

    // 6. A stuck 'submitting' row without a hash (crash before write-ahead)
    //    is reopened by the scheduled reconciler, which requires its token.
    let stuck = h.prepare(3_000_000).await;
    sqlx::query("UPDATE account_smart_account_payments SET status='submitting', updated_at_unix=updated_at_unix-500, created_at_unix=created_at_unix-500 WHERE id=$1")
        .bind(Uuid::parse_str(stuck["id"].as_str().unwrap()).unwrap()).execute(&h.db).await.unwrap();
    let job = format!("{}/internal/payments/reconcile", h.base);
    assert_eq!(h.c.get(&job).send().await.unwrap().status(), 401);
    assert_eq!(
        h.c.get(&job)
            .bearer_auth("wrong-token-wrong-token-wrong-token-x")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let r: Value =
        h.c.get(&job)
            .bearer_auth("test-reconcile-token-that-is-at-least-32-bytes")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(r["changed"].as_u64().unwrap() >= 1, "{r}");
    assert_eq!(h.row(stuck["id"].as_str().unwrap()).await.0, "prepared");
}
