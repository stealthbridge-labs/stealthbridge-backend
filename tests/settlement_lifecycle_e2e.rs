//! End-to-end HTTP + PostgreSQL + SDK + (optional live Stellar Testnet RPC)
//! controlled Testnet settlement lifecycle integration suite.

use axum::{serve, Router};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use stealthbridge_backend::server::{router, AppState};
use uuid::Uuid;

const SECRET: &[u8] = b"isolated-ci-settlement-bridge-secret-32-bytes";
const PATH: &str = "/v1/account/settlements";
const DOMAIN: &str = "stealthbridge-settlement-lifecycle-v1";

fn signed(
    client: &reqwest::Client,
    base: &str,
    account: &str,
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
    let text = format!("{DOMAIN}\n{method}\n{PATH}\n{account}\n{stamp}\n{raw_nonce}\n{digest}\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(text.as_bytes());
    client
        .request(method.parse().unwrap(), format!("{base}{PATH}"))
        .header("x-stealthbridge-account", account)
        .header("x-stealthbridge-issued-at", stamp)
        .header("x-stealthbridge-nonce", raw_nonce)
        .header(
            "x-stealthbridge-signature",
            hex::encode(mac.finalize().into_bytes()),
        )
        .header("content-type", "application/json")
        .body(body.to_owned())
}

fn verify_with_sdk(data: &Value) {
    let Ok(entry) = std::env::var("STEALTHBRIDGE_SDK_ENTRY") else {
        return;
    };
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            r#"
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const {
  validSettlementLifecycleDirectory,
  canonicalSettlementIntentDigest,
  canonicalCustomerAuthorizationDigest,
} = await import(pathToFileURL(process.env.STEALTHBRIDGE_SDK_ENTRY).href);
const dir = JSON.parse(readFileSync(0, 'utf8'));
assert.equal(validSettlementLifecycleDirectory(dir, dir.account_address), true);
const first = dir.items[0];
const recomputed = await canonicalSettlementIntentDigest(dir.account_address, {
  id: first.id,
  organization_id: first.organization_id,
  instruction_id: first.instruction_id,
  corridor_id: first.corridor_id,
  route_fingerprint: first.route_fingerprint,
  idempotency_key: first.idempotency_key,
  asset_code: first.asset_code,
  asset_issuer: first.asset_issuer,
  amount_minor_units: first.amount_minor_units,
  recipient_address: first.recipient_address,
  privacy_rail: first.privacy_rail,
  expires_in_seconds: first.expires_at_unix - first.created_at_unix,
});
assert.equal(recomputed, first.request_sha256);
if (first.customer_auth_sha256) {
  assert.equal(
    await canonicalCustomerAuthorizationDigest(dir.account_address, first.request_sha256),
    first.customer_auth_sha256,
  );
}
console.log('Verified settlement lifecycle directory and digest parity with built @stealthbridge/sdk');
"#,
        ])
        .env("STEALTHBRIDGE_SDK_ENTRY", entry)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(data).unwrap())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

#[tokio::test]
async fn end_to_end_settlement_lifecycle_postgres_sdk_and_optional_live_testnet() {
    let db = PgPool::connect(&std::env::var("DATABASE_URL").expect("isolated CI PostgreSQL"))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    std::env::set_var("STEALTHBRIDGE_SETTLEMENT_LIFECYCLE_ENABLED", "true");
    std::env::set_var(
        "STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET",
        std::str::from_utf8(SECRET).unwrap(),
    );

    let sk = SigningKey::from_bytes(&[19u8; 32]);
    let owner = stellar_strkey::ed25519::PublicKey(sk.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let other = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";

    let state = AppState::from_env().await.unwrap();
    let app: Router = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();

    // Unauthenticated access rejected
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
    sqlx::query("INSERT INTO corridors(id,origin_country,destination_country,asset_code,privacy_rail,enabled) VALUES($1,'US','DE','USDC','private-payments',true)")
        .bind(corridor)
        .execute(&db)
        .await
        .unwrap();
    let fp = hex::encode(Sha256::digest(
        format!("StealthBridge route snapshot v1\n{corridor}\nUS\nDE\nUSDC\n\nprivate-payments\n")
            .as_bytes(),
    ));

    let s1 = Uuid::new_v4();
    let create_body = json!({
        "id": s1,
        "organization_id": null,
        "instruction_id": null,
        "corridor_id": corridor,
        "route_fingerprint": fp,
        "idempotency_key": format!("idem-{s1}"),
        "asset_code": "USDC",
        "asset_issuer": null,
        "amount_minor_units": 5_000_000,
        "recipient_address": other,
        "privacy_rail": "private-payments",
        "expires_in_seconds": 3600,
        "quote_evidence": null
    })
    .to_string();

    // PUT creates at quote_unavailable (no fake FX)
    let res = signed(&client, &base, &owner, "PUT", &create_body, Uuid::new_v4())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let created: Value = res.json().await.unwrap();
    assert_eq!(created["state"], "quote_unavailable");
    assert_eq!(created["payout_status"], "unavailable");
    assert_eq!(created["revision"], 4);
    let req_hash = created["request_sha256"].as_str().unwrap().to_owned();

    // Idempotent PUT returns 200 OK with idempotent_replay: true
    let replay_res = signed(&client, &base, &owner, "PUT", &create_body, Uuid::new_v4())
        .send()
        .await
        .unwrap();
    assert_eq!(replay_res.status(), 200);
    let replay_json: Value = replay_res.json().await.unwrap();
    assert_eq!(replay_json["idempotent_replay"], true);

    // Mutating amount with same idempotency_key returns 409 Conflict
    let mut bad_mut = serde_json::from_str::<Value>(&create_body).unwrap();
    bad_mut["amount_minor_units"] = json!(9_999_999);
    assert_eq!(
        signed(
            &client,
            &base,
            &owner,
            "PUT",
            &bad_mut.to_string(),
            Uuid::new_v4()
        )
        .send()
        .await
        .unwrap()
        .status(),
        409
    );

    // Other account cannot advance OWNER's settlement (tenant/account isolation)
    let verify_policy = json!({
        "action": "verify_policy",
        "id": s1,
        "expected_revision": 4,
        "policy_commitment_sha256": "a".repeat(64)
    })
    .to_string();
    assert_eq!(
        signed(
            &client,
            &base,
            other,
            "POST",
            &verify_policy,
            Uuid::new_v4()
        )
        .send()
        .await
        .unwrap()
        .status(),
        409
    );

    // Stage 5: Verify policy -> revision 5
    let r5: Value = signed(
        &client,
        &base,
        &owner,
        "POST",
        &verify_policy,
        Uuid::new_v4(),
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(r5["state"], "policy_verified");
    assert_eq!(r5["revision"], 5);

    // Stage 6 & 7: Authorize with real Ed25519 signature + unverified privacy flag -> halts at privacy_proof_pending
    let auth_digest = hex::encode(Sha256::digest(
        format!("stealthbridge-auth-v1\n{owner}\n{req_hash}\n").as_bytes(),
    ));
    let ed_sig = hex::encode(sk.sign(req_hash.as_bytes()).to_bytes());
    let auth_halt = json!({
        "action": "authorize",
        "id": s1,
        "expected_revision": 5,
        "customer_auth_sha256": auth_digest,
        "ed25519_signature_hex": ed_sig,
        "acknowledge_transparent_testnet_only": false,
        // Audit C-4: a client claim of proof verification must NOT be trusted.
        "privacy_rail_proof_verified": true
    })
    .to_string();
    let r6: Value = signed(&client, &base, &owner, "POST", &auth_halt, Uuid::new_v4())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r6["state"], "privacy_proof_pending");
    assert_eq!(r6["revision"], 6);
    let claimed_private: bool = sqlx::query_scalar(
        "SELECT privacy_rail_verified FROM account_settlement_lifecycles WHERE id=$1",
    )
    .bind(s1)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(!claimed_private, "client privacy claim must not be trusted");

    // Cancel path from privacy_proof_pending on s1 cleanly recorded
    let cancel_s1 = json!({ "action": "cancel", "id": s1, "expected_revision": 6 }).to_string();
    let r7: Value = signed(&client, &base, &owner, "POST", &cancel_s1, Uuid::new_v4())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r7["state"], "cancelled");

    // Second lifecycle s2: full transparent Testnet leg -> submit -> optional live RPC observe -> reconcile
    let s2 = Uuid::new_v4();
    let s2_body = json!({
        "id": s2,
        "organization_id": null,
        "instruction_id": null,
        "corridor_id": corridor,
        "route_fingerprint": fp,
        "idempotency_key": format!("idem-{s2}"),
        "asset_code": "USDC",
        "asset_issuer": null,
        "amount_minor_units": 1_000_000,
        "recipient_address": other,
        "privacy_rail": "private-payments",
        "expires_in_seconds": 3600,
        "quote_evidence": null
    })
    .to_string();
    let s2_res: Value = signed(&client, &base, &owner, "PUT", &s2_body, Uuid::new_v4())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let s2_hash = s2_res["request_sha256"].as_str().unwrap().to_owned();
    assert_eq!(
        signed(
            &client,
            &base,
            &owner,
            "POST",
            &json!({"action":"verify_policy","id":s2,"expected_revision":4,"policy_commitment_sha256":"b".repeat(64)}).to_string(),
            Uuid::new_v4()
        )
        .send()
        .await
        .unwrap()
        .status(),
        200
    );
    let s2_auth_digest = hex::encode(Sha256::digest(
        format!("stealthbridge-auth-v1\n{owner}\n{s2_hash}\n").as_bytes(),
    ));
    let s2_sig = hex::encode(sk.sign(s2_hash.as_bytes()).to_bytes());
    let s2_auth: Value = signed(
        &client,
        &base,
        &owner,
        "POST",
        &json!({
            "action": "authorize",
            "id": s2,
            "expected_revision": 5,
            "customer_auth_sha256": s2_auth_digest,
            "ed25519_signature_hex": s2_sig,
            "acknowledge_transparent_testnet_only": true,
            "privacy_rail_proof_verified": false
        })
        .to_string(),
        Uuid::new_v4(),
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(s2_auth["state"], "privacy_proof_verified");

    // If caller supplies a real live Testnet tx hash, submit and observe it via real Stellar Testnet RPC!
    if let Ok(live_tx) = std::env::var("STEALTHBRIDGE_TESTNET_TX_HASH") {
        let sub: Value = signed(
            &client,
            &base,
            &owner,
            "POST",
            &json!({"action":"submit_tx","id":s2,"expected_revision":6,"testnet_tx_hash":live_tx})
                .to_string(),
            Uuid::new_v4(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(sub["state"], "tx_submitted");

        // Audit C-5: STEALTHBRIDGE_TESTNET_TX_HASH is any real, successful
        // Testnet transaction that is NOT this intent's payment (e.g. a contract
        // deployment). Inclusion alone used to finalize the settlement; it must
        // now be refused with 422 and leave the state untouched.
        let obs = signed(
            &client,
            &base,
            &owner,
            "POST",
            &json!({"action":"observe_tx","id":s2,"expected_revision":7}).to_string(),
            Uuid::new_v4(),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(obs.status(), 422);
        let still: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM account_settlement_lifecycles WHERE id=$1 AND state='tx_submitted' AND chain_status IS NULL",
        )
        .bind(s2)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(still, 1);
    }

    // Read full GET directory and verify atomicity + outbox + built @stealthbridge/sdk parity!
    let dir: Value = signed(&client, &base, &owner, "GET", "", Uuid::new_v4())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dir["mainnet_enabled"], false);
    assert_eq!(dir["live_fx_enabled"], false);
    assert_eq!(dir["fiat_payouts_enabled"], false);
    verify_with_sdk(&dir);

    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_settlement_outbox WHERE account_address=$1",
    )
    .bind(&owner)
    .fetch_one(&db)
    .await
    .unwrap();
    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM account_settlement_events WHERE account_address=$1",
    )
    .bind(&owner)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(outbox_count, event_count);
    assert!(outbox_count >= 13);

    // Cleanup test fixtures cleanly
    for id in [s1, s2] {
        sqlx::query(
            "DELETE FROM account_settlement_outbox WHERE account_address=$1 AND settlement_id=$2",
        )
        .bind(&owner)
        .bind(id)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM account_settlement_events WHERE account_address=$1 AND settlement_id=$2",
        )
        .bind(&owner)
        .bind(id)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("DELETE FROM account_settlement_lifecycles WHERE account_address=$1 AND id=$2")
            .bind(&owner)
            .bind(id)
            .execute(&db)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM account_settlement_receipts WHERE account_address=$1")
        .bind(&owner)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM corridors WHERE id=$1")
        .bind(corridor)
        .execute(&db)
        .await
        .unwrap();
    task.abort();
}
