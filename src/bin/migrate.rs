//! Explicit, one-shot PostgreSQL schema migration for an operator-approved database.
//! Never called from Vercel request handlers or application startup.
//! No credentials, connection strings or SQL statement payloads are logged.
use sqlx::postgres::PgPoolOptions;
use std::{env, process, time::Duration};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1] != "--apply" {
        eprintln!("Usage: cargo run --bin migrate -- --apply");
        eprintln!("Requires DATABASE_URL; only run against a verified operator-selected database.");
        process::exit(2);
    }
    let url = match env::var("DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!("DATABASE_URL is not configured; no migrations applied.");
            process::exit(2);
        }
    };
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(8))
        .connect(&url)
        .await
    {
        Ok(pool) => pool,
        Err(_) => {
            eprintln!("Database connection failed; confirm TLS, credentials and network access.");
            process::exit(1);
        }
    };
    let result = sqlx::migrate!("./migrations").run(&pool).await;
    pool.close().await;
    match result {
        Ok(()) => println!("PostgreSQL schema migrations applied successfully; no corridors seeded."),
        Err(_) => {
            eprintln!("Migration failed; check the existing schema and migration history before retrying.");
            process::exit(1);
        }
    }
}
