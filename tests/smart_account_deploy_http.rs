//! HTTP + PostgreSQL tests for relayed smart-account deployments.
//! Offline by default. With STEALTHBRIDGE_LIVE_RELAYER_SECRET set, the
//! second test performs a real Testnet deployment through the HTTP API.
use axum::{serve, Router};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use stealthbridge_backend::server::{router, AppState};
use uuid::Uuid;

const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
const SECRET: &[u8] = b"isolated-ci-smart-account-deploy-bridge-secret-32";
const DOMAIN: &str = "stealthbridge-smart-account-deploy-v1";
const PATH: &str = "/v1/account/smart-accounts/deployments";
const FACTORY: &str = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";

fn signed(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    body: &str,
    nonce: Option<Uuid>,
) -> reqwest::RequestBuilder {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let (raw_nonce, digest) = if method == "GET" {
        (String::new(), String::new())
    } else {
        (
            nonce.unwrap().to_string(),
            hex::encode(Sha256::digest(body.as_bytes())),
        )
    };
    let text = format!("{DOMAIN}\n{method}\n{PATH}\n{OWNER}\n{stamp}\n{raw_nonce}\n{digest}\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(text.as_bytes());
    client
        .request(method.parse().unwrap(), format!("{base}{PATH}"))
        .header("x-stealthbridge-account", OWNER)
        .header("x-stealthbridge-issued-at", stamp)
        .header("x-stealthbridge-nonce", raw_nonce)
        .header(
            "x-stealthbridge-signature",
            hex::encode(mac.finalize().into_bytes()),
        )
        .header("content-type", "application/json")
        .body(body.to_owned())
}

async fn start() -> (String, PgPool, tokio::task::JoinHandle<()>) {
    let db = PgPool::connect(&std::env::var("DATABASE_URL").expect("isolated CI PostgreSQL"))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    std::env::set_var(
        "STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET",
        std::str::from_utf8(SECRET).unwrap(),
    );
    let state = AppState::from_env().await.unwrap();
    let app: Router = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { serve(listener, app).await.unwrap() });
    (base, db, task)
}

fn p256_hex() -> String {
    let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes())
}

#[tokio::test]
async fn deployment_api_is_authenticated_configured_and_never_records_unsubmitted_accounts() {
    if std::env::var("STEALTHBRIDGE_LIVE_RELAYER_SECRET").is_ok() {
        return; // the live test owns the environment in that mode
    }
    // Unreachable RPC: any network step must fail without writing a row.
    std::env::set_var("STELLAR_RPC_URL", "https://127.0.0.1:9/rpc");
    std::env::remove_var("STEALTHBRIDGE_RELAYER_SECRET");
    let (base, db, task) = start().await;
    let client = reqwest::Client::new();
    sqlx::query("DELETE FROM account_smart_account_deployments WHERE account_address=$1")
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();

    assert_eq!(
        client
            .get(format!("{base}{PATH}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    let body = json!({"label":"Everyday","public_key_hex":p256_hex(),"credential_id":"AbCdEfGhIjKlMnOpQrSt","wallet_guardian":true}).to_string();
    // Relayer not configured => 503 with an explicit code.
    let res = signed(&client, &base, "POST", &body, Some(Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503);
    // The sanitizing error middleware preserves this endpoint's body as `details`.
    assert_eq!(
        res.json::<Value>().await.unwrap()["details"]["code"],
        "RELAYER_NOT_CONFIGURED"
    );

    std::env::set_var(
        "STEALTHBRIDGE_RELAYER_SECRET",
        stellar_strkey::Unredacted(&stellar_strkey::ed25519::PrivateKey([8; 32]))
            .to_string()
            .as_str(),
    );
    std::env::set_var("STEALTHBRIDGE_SMART_ACCOUNT_FACTORY", FACTORY);
    std::env::set_var("STEALTHBRIDGE_WEBAUTHN_RP_ID", "stealthbridge.vercel.app");

    // Malformed passkey key => 400.
    let bad = json!({"label":"x","public_key_hex":"04abcd","credential_id":"AbCdEfGhIjKlMnOpQrSt","wallet_guardian":false}).to_string();
    assert_eq!(
        signed(&client, &base, "POST", &bad, Some(Uuid::new_v4()))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // RPC unreachable => 502, and no deployment row is written.
    let nonce = Uuid::new_v4();
    assert_eq!(
        signed(&client, &base, "POST", &body, Some(nonce))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    // The nonce is single-use.
    assert_eq!(
        signed(&client, &base, "POST", &body, Some(nonce))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );

    let listed: Value = signed(&client, &base, "GET", "", None)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["relayer_configured"], true);
    assert_eq!(listed["deployments"].as_array().unwrap().len(), 0);
    task.abort();
}

#[tokio::test]
async fn live_testnet_deployment_through_http_api() {
    let Ok(secret) = std::env::var("STEALTHBRIDGE_LIVE_RELAYER_SECRET") else {
        return;
    };
    std::env::remove_var("STELLAR_RPC_URL");
    std::env::set_var("STEALTHBRIDGE_RELAYER_SECRET", &secret);
    std::env::set_var("STEALTHBRIDGE_SMART_ACCOUNT_FACTORY", FACTORY);
    std::env::set_var("STEALTHBRIDGE_WEBAUTHN_RP_ID", "stealthbridge.vercel.app");
    let (base, _db, task) = start().await;
    let client = reqwest::Client::new();
    let body = json!({"label":"Live HTTP","public_key_hex":p256_hex(),"credential_id":"LiveHttpCredential01","wallet_guardian":true}).to_string();
    let res = signed(&client, &base, "POST", &body, Some(Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    let status = res.status();
    let created: Value = res.json().await.unwrap();
    assert_eq!(status, 202, "{created}");
    println!("LIVE submitted {created}");
    let contract = created["contract_address"].as_str().unwrap().to_owned();
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let listed: Value = signed(&client, &base, "GET", "", None)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = listed["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["contract_address"] == contract.as_str())
            .unwrap()
            .clone();
        if row["status"] == "deployed" {
            println!("LIVE deployed {row}");
            assert!(row["ledger"].as_i64().unwrap() > 0);
            assert_eq!(row["guardian_address"], OWNER);
            task.abort();
            return;
        }
    }
    panic!("deployment not confirmed on-chain");
}
