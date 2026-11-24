//! Real HTTP + PostgreSQL regression tests for business operations
//! (audit H-5 tenant status, H-3 webhook secret rotation). Test-only HMAC.
use axum::{serve, Router};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use stealthbridge_backend::server::{router, AppState};
use uuid::Uuid;

const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
const SECRET: &[u8] = b"isolated-ci-business-ops-bridge-secret-32-bytes";
const DOMAIN: &str = "stealthbridge-business-webhooks-v1";
const PATH: &str = "/v1/business/webhooks";

fn signed_put(client: &reqwest::Client, base: &str, body: &str) -> reqwest::RequestBuilder {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let nonce = Uuid::new_v4().to_string();
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    let text = format!("{DOMAIN}\nPUT\n{PATH}\n{OWNER}\n{stamp}\n{nonce}\n{digest}\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(text.as_bytes());
    client
        .put(format!("{base}{PATH}"))
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

async fn stored_hash(db: &PgPool, org: Uuid, id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT secret_sha256 FROM business_webhooks WHERE organization_id=$1 AND id=$2",
    )
    .bind(org)
    .bind(id)
    .fetch_one(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn pending_orgs_are_refused_and_webhook_rotation_keeps_hash_consistent() {
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
    let client = reqwest::Client::new();

    let org = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES($1,'Tenancy regression','pending')")
        .bind(org)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,'owner')",
    )
    .bind(org)
    .bind(OWNER)
    .execute(&db)
    .await
    .unwrap();

    let hook = Uuid::new_v4();
    let body = json!({"organization_id":org,"id":hook,
        "endpoint_url":"https://hooks.tenancy-test.example/stealthbridge",
        "subscribed_events":"settlement.updated","enabled":true})
    .to_string();

    // H-5: a self-registered, unverified (pending) organization is refused,
    // even though the caller is its owner.
    let res = signed_put(&client, &base, &body).send().await.unwrap();
    assert_eq!(res.status(), 403);

    sqlx::query("UPDATE organizations SET status='active' WHERE id=$1")
        .bind(org)
        .execute(&db)
        .await
        .unwrap();

    // H-3: every upsert returns a fresh secret, and the stored hash must be
    // the hash of the secret most recently returned.
    let first: Value = signed_put(&client, &base, &body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let s1 = first["signing_secret_once"].as_str().unwrap().to_owned();
    assert_eq!(
        stored_hash(&db, org, hook).await,
        hex::encode(Sha256::digest(s1.as_bytes()))
    );

    let second: Value = signed_put(&client, &base, &body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let s2 = second["signing_secret_once"].as_str().unwrap().to_owned();
    assert_ne!(s1, s2);
    assert_eq!(
        stored_hash(&db, org, hook).await,
        hex::encode(Sha256::digest(s2.as_bytes()))
    );

    // Suspended tenants are refused as well.
    sqlx::query("UPDATE organizations SET status='suspended' WHERE id=$1")
        .bind(org)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        signed_put(&client, &base, &body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    task.abort();
}
