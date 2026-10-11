//! Operator CLI for recording actual corridor *candidates* without advertising
//! liquidity, private transfers, or provider availability. Deliberately lacks
//! an enable action; operator verification is a separate reviewed process.
use sqlx::postgres::PgPoolOptions;
use std::{env, process, time::Duration};
use uuid::Uuid;
use stealthbridge_backend::wallet::decode_account_address;

#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    origin: String,
    destination: String,
    asset_code: String,
    asset_issuer: Option<String>,
    privacy_rail: String,
}

fn parse_candidate(values: &[String]) -> Result<Candidate, &'static str> {
    if values.len() != 5 {
        return Err("expected: register ORIGIN DESTINATION ASSET_CODE ISSUER_OR_DASH PRIVACY_RAIL");
    }
    let country = |value: &str| value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase());
    if !country(&values[0]) || !country(&values[1]) || values[0] == values[1] {
        return Err("countries must be different two-letter uppercase ISO country codes");
    }
    if values[2].is_empty() || values[2].len() > 64
        || !values[2].bytes().all(|b| b.is_ascii_alphanumeric() || b"_-:".contains(&b))
    {
        return Err("asset code must contain 1-64 ASCII letters, numbers, _, - or :");
    }
    // Syntax screening only, not issuer authorization, asset existence or token verification.
    let issuer = if values[3] == "-" {
        None
    } else if decode_account_address(&values[3]).is_some()
    {
        Some(values[3].clone())
    } else {
        return Err("issuer must be '-' or a checksum-valid classic Stellar G-address");
    };
    if !["private-payments", "confidential-token"].contains(&values[4].as_str()) {
        return Err("privacy rail must be private-payments or confidential-token");
    }
    Ok(Candidate {
        origin: values[0].clone(),
        destination: values[1].clone(),
        asset_code: values[2].clone(),
        asset_issuer: issuer,
        privacy_rail: values[4].clone(),
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("register") {
        eprintln!("Usage: cargo run --bin corridor-admin -- register ORIGIN DESTINATION ASSET_CODE ISSUER_OR_DASH PRIVACY_RAIL");
        eprintln!("Always registers disabled candidates; never authorizes money movement.");
        process::exit(2);
    }
    let candidate = match parse_candidate(&args[1..]) {
        Ok(candidate) => candidate,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };
    let url = match env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("DATABASE_URL is required; no candidate was registered.");
            process::exit(2);
        }
    };
    let pool = match PgPoolOptions::new().max_connections(1)
        .acquire_timeout(Duration::from_secs(8)).connect(&url).await
    {
        Ok(pool) => pool,
        Err(_) => {
            eprintln!("Unable to connect to PostgreSQL; check credentials, TLS and migrations.");
            process::exit(1);
        }
    };
    let id = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO corridors (id, origin_country, destination_country, asset_code, asset_issuer, privacy_rail, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, FALSE)",
    )
    .bind(id)
    .bind(&candidate.origin)
    .bind(&candidate.destination)
    .bind(&candidate.asset_code)
    .bind(&candidate.asset_issuer)
    .bind(&candidate.privacy_rail)
    .execute(&pool)
    .await;
    pool.close().await;
    match result {
        Ok(_) => println!("Candidate {id} registered with enabled=false; invisible to public discovery."),
        Err(_) => {
            eprintln!("Corridor registration failed; no public capability was enabled.");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<String> {
        ["NG", "GH", "USDC", "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX", "confidential-token"]
            .into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn accepts_disabled_candidate_with_syntax_checked_issuer() {
        let candidate = parse_candidate(&valid()).unwrap();
        assert_eq!(candidate.origin, "NG");
        assert_eq!(candidate.asset_issuer.unwrap().len(), 56);
    }

    #[test]
    fn rejects_same_country_and_invalid_rail() {
        let mut values = valid();
        values[1] = "NG".into();
        assert!(parse_candidate(&values).is_err());
        values[1] = "GH".into();
        values[4] = "live-payout".into();
        assert!(parse_candidate(&values).is_err());
    }

    #[test]
    fn rejects_issuer_with_valid_shape_but_invalid_stellar_checksum() {
        let mut values = valid();
        values[3] = "G".to_owned() + &"A".repeat(55);
        assert!(parse_candidate(&values).is_err());
        values[3] = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZA".into();
        assert!(parse_candidate(&values).is_err());
    }
    #[test]
    fn permits_unknown_issuer_as_null_only() {
        let mut values = valid();
        values[3] = "-".into();
        assert_eq!(parse_candidate(&values).unwrap().asset_issuer, None);
        values[3] = "not-an-issuer".into();
        assert!(parse_candidate(&values).is_err());
    }
}
