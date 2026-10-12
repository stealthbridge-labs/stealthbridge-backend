//! Dedicated, supervised, read-only Stellar Testnet observation worker.
//! Must run as a long-lived process, never as a Vercel Function or web handler.
use std::env;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_|EnvFilter::new("info")))
        .init();
    if env::var("STEALTHBRIDGE_WORKER_MODE").ok().as_deref()!=Some("readonly-testnet-observer"){
        return Err("Explicit STEALTHBRIDGE_WORKER_MODE=readonly-testnet-observer required".into());
    }
    if env::var("DATABASE_URL").ok().filter(|url|!url.is_empty()).is_none(){
        return Err("Dedicated observer requires PostgreSQL DATABASE_URL".into());
    }
    let state=stealthbridge_backend::server::AppState::from_env().await?;
    tracing::info!("Starting isolated Stellar Testnet observation worker");
    stealthbridge_backend::server::run_ledger_observer(state).await;
    Ok(())
}
