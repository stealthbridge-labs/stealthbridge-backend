//! Opt-in END-TO-END test of passkey-authorized smart-account payments on a
//! LOCAL Stellar quickstart network (never Testnet, never Mainnet).
//!
//! Real components: factory + smart-account WASM deployed on the local
//! network, the Rust relayer, the HTTP API, PostgreSQL, Soroban host
//! __check_auth. The only stand-in is the authenticator: a software P-256 key
//! produces a byte-exact WebAuthn assertion (authenticatorData, clientDataJSON,
//! DER signature) like a passkey would.
//!
//! Run (see CLAUDE.md "Local network E2E"):
//!   STEALTHBRIDGE_LOCAL_E2E=1 STEALTHBRIDGE_ALLOW_LOCAL_NETWORK=true \
//!   STELLAR_RPC_URL=http://localhost:8000/rpc STEALTHBRIDGE_RELAYER_SECRET=S... \
//!   STEALTHBRIDGE_SMART_ACCOUNT_FACTORY=C... DATABASE_URL=postgres://... \
//!   cargo test --test payments_local_e2e -- --nocapture
use axum::serve;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stealthbridge_backend::{
    relayer,
    server::{router, AppState},
    smart_account_payments as pay,
};
use uuid::Uuid;

const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
const SECRET: &[u8] = b"isolated-local-e2e-bridge-secret-at-least-32-bytes";
const RP: &str = "stealthbridge.vercel.app";

fn signed(
    c: &reqwest::Client,
    base: &str,
    domain: &str,
    path: &str,
    method: &str,
    body: &str,
) -> reqwest::RequestBuilder {
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
        format!("{domain}\n{method}\n{path}\n{OWNER}\n{stamp}\n{nonce}\n{digest}\n").as_bytes(),
    );
    c.request(method.parse().unwrap(), format!("{base}{path}"))
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

const DEPLOY: (&str, &str) = (
    "stealthbridge-smart-account-deploy-v1",
    "/v1/account/smart-accounts/deployments",
);
const PAY: (&str, &str) = (
    "stealthbridge-smart-account-payments-v1",
    "/v1/account/smart-accounts/payments",
);
const BAL: (&str, &str) = (
    "stealthbridge-smart-account-balances-v1",
    "/v1/account/smart-accounts/balances",
);

fn assertion(key: &SigningKey, challenge: &str, flags: u8) -> Value {
    let mut ad = relayer::rp_id_hash(RP).to_vec();
    ad.push(flags);
    ad.extend_from_slice(&1u32.to_be_bytes());
    let cd = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{RP}","crossOrigin":false}}"#).into_bytes();
    let mut signed = ad.clone();
    signed.extend_from_slice(&Sha256::digest(&cd));
    let digest: [u8; 32] = Sha256::digest(&signed).into();
    let sig: Signature = key.sign_prehash(&digest).unwrap();
    json!({"authenticator_data": pay::b64url(&ad), "client_data_json": pay::b64url(&cd), "signature": pay::b64url(sig.to_der().as_bytes())})
}

async fn fund_smart_account(
    state: &AppState,
    funder: &ed25519_dalek::SigningKey,
    account: &str,
    stroops: i64,
) {
    // A G-account pays into the C-address via the native SAC; the funder is
    // the transaction source, so its authorization is the envelope signature.
    let passphrase = relayer::network_passphrase(state).await.unwrap();
    let token = pay::PayAsset::parse("XLM")
        .unwrap()
        .contract_id(&passphrase)
        .unwrap();
    let funder_g =
        stellar_strkey::ed25519::PublicKey(funder.verifying_key().to_bytes()).to_string();
    let call = pay::transfer_args(token, funder_g.as_str(), account, stroops).unwrap();
    let source = funder.verifying_key().to_bytes();
    let rpc = |m: &'static str, p: Value| async move {
        reqwest::Client::new()
            .post(std::env::var("STELLAR_RPC_URL").unwrap())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":m,"params":p}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["result"]
            .clone()
    };
    let acct = rpc("getLedgerEntries", json!({"keys":[]})).await;
    let _ = acct;
    let seq = {
        use stellar_xdr::{
            AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr,
            Uint256, WriteXdr,
        };
        let k = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(source))),
        });
        let r = rpc(
            "getLedgerEntries",
            json!({"keys":[relayer::b64(&k.to_xdr(Limits::none()).unwrap())]}),
        )
        .await;
        let bytes = base64_decode(r["entries"][0]["xdr"].as_str().unwrap());
        match LedgerEntryData::from_xdr(&bytes, Limits::none()).unwrap() {
            LedgerEntryData::Account(a) => a.seq_num.0,
            _ => panic!(),
        }
    };
    let tx = pay::invoke_tx(source, seq + 1, call.clone(), vec![]).unwrap();
    let env = |t: &stellar_xdr::Transaction| {
        use stellar_xdr::{Limits, TransactionEnvelope, TransactionV1Envelope, WriteXdr};
        relayer::b64(
            &TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: t.clone(),
                signatures: vec![].try_into().unwrap(),
            })
            .to_xdr(Limits::none())
            .unwrap(),
        )
    };
    let sim = rpc("simulateTransaction", json!({"transaction": env(&tx)})).await;
    let auth: Vec<stellar_xdr::SorobanAuthorizationEntry> = sim["results"][0]["auth"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            use stellar_xdr::{Limits, ReadXdr};
            stellar_xdr::SorobanAuthorizationEntry::from_xdr(
                base64_decode(a.as_str().unwrap()),
                Limits::none(),
            )
            .unwrap()
        })
        .collect();
    let tx = pay::invoke_tx(source, seq + 1, call, auth).unwrap();
    let sim = rpc("simulateTransaction", json!({"transaction": env(&tx)})).await;
    let ready = relayer::assemble_signed(tx, &sim).unwrap();
    let hash = relayer::transaction_hash(&ready, &passphrase);
    let signed = relayer::sign(ready, &passphrase, funder);
    use stellar_xdr::{Limits, WriteXdr};
    rpc(
        "sendTransaction",
        json!({"transaction": relayer::b64(&signed.to_xdr(Limits::none()).unwrap())}),
    )
    .await;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if rpc("getTransaction", json!({"hash": hash})).await["status"] == "SUCCESS" {
            return;
        }
    }
    panic!("funding did not confirm");
}

fn base64_decode(s: &str) -> Vec<u8> {
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

#[tokio::test]
async fn passkey_authorizes_a_real_smart_account_payment_end_to_end() {
    if std::env::var("STEALTHBRIDGE_LOCAL_E2E").is_err() {
        return;
    }
    let db = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    std::env::set_var(
        "STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET",
        std::str::from_utf8(SECRET).unwrap(),
    );
    std::env::set_var("STEALTHBRIDGE_WEBAUTHN_RP_ID", RP);
    let state = AppState::from_env().await.unwrap();
    let probe = AppState::from_env().await.unwrap();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { serve(listener, app).await.unwrap() });
    let c = reqwest::Client::new();

    // 1. Customer creates a passkey smart account (relayed factory call).
    let passkey = SigningKey::random(&mut rand_core::OsRng);
    let pk = hex::encode(passkey.verifying_key().to_encoded_point(false).as_bytes());
    let body = json!({"label":"E2E","public_key_hex":pk,"credential_id":"LocalE2ECredential0001","wallet_guardian":true}).to_string();
    let res = signed(&c, &base, DEPLOY.0, DEPLOY.1, "POST", &body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let account = res.json::<Value>().await.unwrap()["contract_address"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let d: Value = signed(&c, &base, DEPLOY.0, DEPLOY.1, "GET", "")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if d["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["contract_address"] == account.as_str() && x["status"] == "deployed")
        {
            break;
        }
    }
    println!("E2E account {account}");

    // 2. Fund it with 100 XLM from the funder (relayer key on the local net).
    let funder =
        relayer::relayer_key(&std::env::var("STEALTHBRIDGE_RELAYER_SECRET").unwrap()).unwrap();
    fund_smart_account(&probe, &funder, &account, 1_000_000_000).await;

    // 3. Prepare a 12.5 XLM payment to a fresh destination.
    let dest_key = ed25519_dalek::SigningKey::from_bytes(
        &rand_core::RngCore::next_u64(&mut rand_core::OsRng)
            .to_le_bytes()
            .repeat(4)
            .try_into()
            .unwrap(),
    );
    let dest = stellar_strkey::ed25519::PublicKey(dest_key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let prep = |amount: i64| {
        json!({"action":"prepare","contract_address":account,"destination":dest,"asset":"XLM","amount_stroops":amount}).to_string()
    };
    let res = signed(&c, &base, PAY.0, PAY.1, "POST", &prep(125_000_000))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let intent: Value = res.json().await.unwrap();
    let id = intent["id"].as_str().unwrap().to_owned();
    let challenge = intent["challenge"].as_str().unwrap().to_owned();
    // The client can recompute the challenge from the returned preimage.
    let preimage = base64_decode(intent["authorization_preimage_xdr"].as_str().unwrap());
    assert_eq!(pay::b64url(&Sha256::digest(&preimage)), challenge);

    let submit = |a: Value| {
        let mut v = a;
        v["action"] = json!("submit");
        v["id"] = json!(id);
        v.to_string()
    };

    // 4a. Tampered: signature over a different challenge is refused (422) and the intent stays usable.
    let wrong = assertion(&passkey, &pay::b64url(&[7u8; 32]), 0x05);
    assert_eq!(
        signed(&c, &base, PAY.0, PAY.1, "POST", &submit(wrong))
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    // 4b. Missing user verification is refused.
    assert_eq!(
        signed(
            &c,
            &base,
            PAY.0,
            PAY.1,
            "POST",
            &submit(assertion(&passkey, &challenge, 0x01))
        )
        .send()
        .await
        .unwrap()
        .status(),
        422
    );
    // 4c. A different key (e.g. the relayer's own) cannot authorize.
    let impostor = SigningKey::random(&mut rand_core::OsRng);
    assert_eq!(
        signed(
            &c,
            &base,
            PAY.0,
            PAY.1,
            "POST",
            &submit(assertion(&impostor, &challenge, 0x05))
        )
        .send()
        .await
        .unwrap()
        .status(),
        422
    );

    // 5. The genuine passkey assertion authorizes and the relayer submits.
    let res = signed(
        &c,
        &base,
        PAY.0,
        PAY.1,
        "POST",
        &submit(assertion(&passkey, &challenge, 0x05)),
    )
    .send()
    .await
    .unwrap();
    let status = res.status();
    let body: Value = res.json().await.unwrap();
    assert_eq!(status, 202, "{body}");
    let tx_hash = body["tx_hash"].as_str().unwrap().to_owned();
    println!("E2E payment tx {tx_hash}");
    // 5b. Replaying the same intent is refused.
    assert_eq!(
        signed(
            &c,
            &base,
            PAY.0,
            PAY.1,
            "POST",
            &submit(assertion(&passkey, &challenge, 0x05))
        )
        .send()
        .await
        .unwrap()
        .status(),
        409
    );

    // 6. Confirmation comes only from chain evidence.
    let mut confirmed = Value::Null;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let l: Value = signed(&c, &base, PAY.0, PAY.1, "GET", "")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let p = l["payments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id.as_str())
            .unwrap()
            .clone();
        if p["status"] == "confirmed" {
            confirmed = p;
            break;
        }
    }
    println!("E2E confirmed {confirmed}");
    assert_eq!(confirmed["status"], "confirmed");
    assert!(confirmed["ledger"].as_i64().unwrap() > 0);

    // 7. Balance reflects exactly the authorized amount.
    let b: Value = signed(&c, &base, BAL.0, BAL.1, "GET", "")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = b["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["contract_address"] == account.as_str())
        .unwrap();
    assert_eq!(row["balances"][0]["balance_stroops"], "875000000");

    // 8. The same signature cannot be reused for a new intent (new nonce => new payload).
    let res = signed(&c, &base, PAY.0, PAY.1, "POST", &prep(125_000_000))
        .send()
        .await
        .unwrap();
    let second: Value = res.json().await.unwrap();
    assert_ne!(second["challenge"], challenge);
    let reuse = {
        let mut v = assertion(&passkey, &challenge, 0x05);
        v["action"] = json!("submit");
        v["id"] = second["id"].clone();
        v.to_string()
    };
    assert_eq!(
        signed(&c, &base, PAY.0, PAY.1, "POST", &reuse)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
}
