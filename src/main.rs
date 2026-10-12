use std::{env, net::SocketAddr};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let state = stealthbridge_backend::server::AppState::from_env().await?;
    // API request-process lifetime must never own durable observer polling.
    if env::var("STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER").ok().as_deref()==Some("true") {
        return Err("The API cannot spawn ledger polling. Run the dedicated ledger-observer binary.".into());
    }
    let app = stealthbridge_backend::server::router(state);
    let port: u16 = env::var("PORT").unwrap_or_else(|_| "8080".to_owned()).parse()?;
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned()).parse()?;
    let address = SocketAddr::new(host, port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "StealthBridge API starting");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
