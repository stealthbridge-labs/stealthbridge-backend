//! Standalone supervised observer. Never installed as a Vercel request function.
use std::{env, time::Duration};
use sqlx::{Connection, postgres::PgConnection};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    if env::var("STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER").ok().as_deref() != Some("true") {
        return Err("Ledger worker is disabled; opt in explicitly on the supervised worker only".into());
    }
    let database_url = env::var("DATABASE_URL")?;
    let mut lease = PgConnection::connect(&database_url).await?;
    if !stealthbridge_backend::observer_lease::try_acquire(&mut lease).await? {
        return Err("Another Testnet ledger observer already holds the database lease".into());
    }
    let state = stealthbridge_backend::server::AppState::from_env().await?;
    let observer = stealthbridge_backend::server::run_ledger_observer(state);
    tokio::pin!(observer);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = &mut observer => {
                return Err("Testnet observer exited unexpectedly; stop worker".into());
            }
            _ = heartbeat.tick() => {
                if !stealthbridge_backend::observer_lease::still_held(&mut lease).await? {
                    return Err("Lost Testnet observer lease; stop all polling".into());
                }
            }
        }
    }
}
