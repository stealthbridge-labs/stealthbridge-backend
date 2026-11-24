//! Opt-in LIVE Stellar Testnet check of the Rust relayer (broadcasts one
//! Testnet transaction paid by the relayer key). Never runs in CI:
//!   STEALTHBRIDGE_RELAYER_SECRET=S... cargo test --test relayer_live_testnet -- --ignored
use stealthbridge_backend::{relayer, server::AppState};

const FACTORY: &str = "CAUJ5FMGDISNYEU7T6EQDYRLFF7CVC5F2PXJVEHQHY7HM275I2X6ITH6";

#[tokio::test]
#[ignore = "broadcasts a Testnet transaction"]
async fn relayer_creates_passkey_style_account_on_testnet() {
    let secret = std::env::var("STEALTHBRIDGE_RELAYER_SECRET").expect("relayer secret");
    let key = relayer::relayer_key(&secret).expect("valid S... secret");
    std::env::remove_var("DATABASE_URL");
    let state = AppState::from_env().await.unwrap();

    // A fresh, real P-256 key: the same key type a WebAuthn passkey produces.
    let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let point = sk.verifying_key().to_encoded_point(false);
    let owner = relayer::SignerKey::secp256r1_from_hex(&hex::encode(point.as_bytes())).unwrap();
    let rp = relayer::rp_id_hash("stealthbridge.vercel.app");

    let deployed = relayer::deploy_account(&state, &key, FACTORY, &owner, rp, None)
        .await
        .expect("relayed deployment");
    println!(
        "LIVE account={} tx={} ledger={}",
        deployed.contract, deployed.tx_hash, deployed.ledger
    );
    assert!(deployed.contract.starts_with('C'));
    assert!(deployed.ledger > 0);
}
