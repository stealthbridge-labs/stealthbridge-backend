//! End-to-end HTTP contract discovery using the real Axum app.
//! No deployed addresses, RPC transactions, mock financial data or wallet keys.
use serde_json::Value;
use stealthbridge_backend::server::{router,AppState};

#[tokio::test]
async fn real_contract_discovery_http_remains_undeployed_and_non_moving(){
    let state=AppState::from_env().await.expect("CI Postgres + read-only config");
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("ephemeral bind");
    let addr=listener.local_addr().expect("local address");
    let task=tokio::spawn(async move{
        axum::serve(listener,router(state)).await.expect("test Axum server");
    });
    let client=reqwest::Client::new();
    let base=format!("http://{addr}");
    let response=client.get(format!("{base}/v1/contracts")).send().await.expect("contracts GET");
    assert_eq!(response.status(),reqwest::StatusCode::OK);
    let body:Value=response.json().await.expect("manifest JSON");
    assert_eq!(body["network"],"testnet");
    assert_eq!(body["manifest"]["status"],"not-deployed");
    assert_eq!(body["manifest"]["verified"],false);
    assert_eq!(body["public_interface"]["status"],"source-interface-only");
    assert_eq!(body["on_chain_verified"],false);
    assert_eq!(body["payment_execution_enabled"],false);
    assert_eq!(body["manifest"]["contractAddresses"].as_object().unwrap().len(),0);
    let methods=body["public_interface"]["contracts"]["policy-registry"]["reads"]
        .as_object().expect("real source method metadata");
    assert!(methods.contains_key("is_effective"));
    assert!(!methods.contains_key("set_rule"));
    let gate=&body["public_interface"]["contracts"]["governance-gate"];
    assert_eq!(gate["source"],"contracts/governance-gate/src/lib.rs");
    assert_eq!(gate["reads"]["public_flags_allow"]["returns"],"bool");
    assert_eq!(gate["reads"]["public_flags_allow"]["args"].as_array().unwrap().len(),2);
    assert_eq!(gate["writes"].as_array().unwrap().len(),0);
    // This source inventory never certifies an on-chain gate deployment.
    assert!(body["manifest"]["contractAddresses"]["governance-gate"].is_null());
    let access=client.post(format!("{base}/v1/settlements"))
       .send().await.expect("disabled write request");
    assert_eq!(access.status(),reqwest::StatusCode::NOT_IMPLEMENTED);
    let capabilities:Value=client.get(format!("{base}/v1/capabilities")).send().await
       .expect("capabilities").json().await.expect("JSON");
    assert_eq!(capabilities["payments_enabled"],false);
    assert_eq!(capabilities["confidential_token_verified"],false);
    task.abort();
}
