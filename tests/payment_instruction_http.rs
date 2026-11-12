//! Real HTTP + PostgreSQL instruction lifecycle, using test-only HMAC/ciphertext.
use axum::{serve, Router};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use stealthbridge_backend::server::{router, AppState};
use uuid::Uuid;
const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
const SECRET: &[u8] = b"isolated-ci-instruction-bridge-secret-32-bytes";
const PATH: &str = "/v1/account/instructions";
fn signed(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    body: &str,
    nonce: Uuid,
) -> reqwest::RequestBuilder {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let digest = if method == "GET" {
        String::new()
    } else {
        hex::encode(Sha256::digest(body.as_bytes()))
    };
    let raw_nonce = if method == "GET" {
        String::new()
    } else {
        nonce.to_string()
    };
    let text=format!("stealthbridge-payment-instructions-v1\n{method}\n{PATH}\n{OWNER}\n{stamp}\n{raw_nonce}\n{digest}\n");
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
fn verify_sdk(data: &Value) {
    let Ok(entry) = std::env::var("STEALTHBRIDGE_SDK_ENTRY") else {
        return;
    };
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child=Command::new("node").args(["--input-type=module","-e",r#"
        import {readFileSync} from 'node:fs';
        import {pathToFileURL} from 'node:url';
        import assert from 'node:assert/strict';
        const {validPaymentInstructionDirectory}=await import(pathToFileURL(process.env.STEALTHBRIDGE_SDK_ENTRY).href);
        const data=JSON.parse(readFileSync(0,'utf8'));
        assert.equal(validPaymentInstructionDirectory(data,data.account_address),true);
        console.log('Verified real HTTP + PostgreSQL instruction response with the built SDK');
    "#]).env("STEALTHBRIDGE_SDK_ENTRY",entry).stdin(Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(data).unwrap())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
#[tokio::test]
async fn signed_http_instructions_persist_and_never_authorize_payment() {
    let db = PgPool::connect(&std::env::var("DATABASE_URL").expect("isolated CI PostgreSQL"))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    std::env::set_var("STEALTHBRIDGE_PAYMENT_INSTRUCTIONS_ENABLED", "true");
    std::env::set_var(
        "STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET",
        std::str::from_utf8(SECRET).unwrap(),
    );
    let state = AppState::from_env().await.unwrap();
    let app: Router = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{base}{PATH}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let corridor = Uuid::new_v4();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO corridors(id,origin_country,destination_country,asset_code,privacy_rail,enabled) VALUES($1,'AA','BB','HTTP_TEST','private-payments',true)").bind(corridor).execute(&db).await.unwrap();
    let fingerprint = hex::encode(Sha256::digest(
        format!(
            "StealthBridge route snapshot v1\n{corridor}\nAA\nBB\nHTTP_TEST\n\nprivate-payments\n"
        )
        .as_bytes(),
    ));
    let body=json!({"id":id,"corridor_id":corridor,"route_fingerprint":fingerprint,"expires_in_seconds":300,
        "encrypted":{"schema_version":1,"network":"testnet","cipher":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256","iterations":600000,"salt":"AAAAAAAAAAAAAAAAAAAAAA","iv":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAA"}}).to_string();
    let nonce = Uuid::new_v4();
    assert_eq!(
        signed(&client, &base, "PUT", &body, nonce)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        signed(&client, &base, "PUT", &body, nonce)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        signed(&client, &base, "PUT", &body, Uuid::new_v4())
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let response = signed(&client, &base, "GET", "", Uuid::new_v4())
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    let data: Value = response.json().await.unwrap();
    assert_eq!(data["payment_execution_enabled"], false);
    verify_sdk(&data);
    assert!(data["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["id"] == id.to_string() && v["state"] == "saved"));
    let cancel = json!({"id":id,"expected_revision":1}).to_string();
    for _ in 0..2 {
        assert_eq!(
            signed(&client, &base, "POST", &cancel, Uuid::new_v4())
                .send()
                .await
                .unwrap()
                .status(),
            204
        );
    }
    let data: Value = signed(&client, &base, "GET", "", Uuid::new_v4())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify_sdk(&data);
    let row = data["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id.to_string())
        .unwrap();
    assert_eq!(row["state"], "cancelled");
    assert_eq!(row["revision"], 2);
    assert!(row["cancelled_at_unix"].as_i64().is_some());
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM customer_payment_instruction_events WHERE account_address=$1 AND instruction_id=$2").bind(OWNER).bind(id).fetch_one(&db).await.unwrap();
    assert_eq!(events, 2);
    let capabilities: Value = client
        .get(format!("{base}/v1/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(capabilities["payments_enabled"], false);
    for table in [
        "customer_payment_instruction_events",
        "customer_payment_instructions",
    ] {
        let key = if table.ends_with("_events") {
            "instruction_id"
        } else {
            "id"
        };
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE account_address=$1 AND {key}=$2"
        ))
        .bind(OWNER)
        .bind(id)
        .execute(&db)
        .await
        .unwrap();
    }
    sqlx::query("DELETE FROM corridors WHERE id=$1")
        .bind(corridor)
        .execute(&db)
        .await
        .unwrap();
    task.abort();
}
