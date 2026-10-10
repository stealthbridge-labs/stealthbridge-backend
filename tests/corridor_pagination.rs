//! Real local HTTP + PostgreSQL coverage for bounded corridor pagination.
//! Fixtures are test-only: no live corridor, issuer, provider, or fiat payouts.
use serde_json::Value;
use sqlx::PgPool;
use stealthbridge_backend::server::{router,AppState};
use uuid::Uuid;

#[tokio::test]
async fn pages_are_ordered_bounded_and_never_invent_provider_data() {
    let url=std::env::var("DATABASE_URL").expect("isolated PostgreSQL service required");
    let pool=PgPool::connect(&url).await.expect("open database");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");

    // Malformed real-world corridor metadata must fail at the database boundary,
    // even if an operator bypasses the application and directly executes SQL.
    let bad_asset = Uuid::new_v4();
    assert!(sqlx::query(
        "INSERT INTO corridors (id,origin_country,destination_country,asset_code,privacy_rail) VALUES ($1,'NG','GH','BAD ASSET','confidential-token')"
    ).bind(bad_asset).execute(&pool).await.is_err());
    let bad_issuer = Uuid::new_v4();
    assert!(sqlx::query(
        "INSERT INTO corridors (id,origin_country,destination_country,asset_code,asset_issuer,privacy_rail) VALUES ($1,'NG','GH','USDC','','confidential-token')"
    ).bind(bad_issuer).execute(&pool).await.is_err());


    let mut fixtures=Vec::new();
    for _ in 0..5 {
        let id=Uuid::new_v4();
        sqlx::query(
            "INSERT INTO corridors (id,origin_country,destination_country,asset_code,privacy_rail,enabled) \
             VALUES ($1,'AA','BB','TEST_FIXTURE','confidential-token',TRUE)"
        ).bind(id).execute(&pool).await.expect("fixture insert");
        fixtures.push(id);
    }

    let state=AppState::from_env().await.expect("Testnet configuration + DB");
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("local listener");
    let addr=listener.local_addr().expect("bound address");
    let server=tokio::spawn(async move {
        axum::serve(listener,router(state)).await.expect("local server");
    });
    let client=reqwest::Client::new();
    let base=format!("http://{addr}");

    let first=client.get(format!("{base}/v1/corridors/page?limit=2"))
        .send().await.expect("first page");
    assert_eq!(first.status(),reqwest::StatusCode::OK);
    let page:Value=first.json().await.expect("page JSON");
    assert_eq!(page["items"].as_array().expect("items").len(),2);
    let cursor=page["next_cursor"].as_str().expect("next cursor");
    assert!(Uuid::parse_str(cursor).is_ok());

    let second=client.get(format!("{base}/v1/corridors/page?limit=2&after={cursor}"))
        .send().await.expect("second page");
    assert_eq!(second.status(),reqwest::StatusCode::OK);
    let next:Value=second.json().await.expect("second page JSON");
    let items=next["items"].as_array().expect("items");
    assert_eq!(items.len(),2);
    for item in items {
        let id=Uuid::parse_str(item["id"].as_str().expect("UUID")).expect("valid UUID");
        assert!(id>Uuid::parse_str(cursor).expect("valid cursor"));
        assert!(item.get("payout_provider").is_none());
        assert!(item.get("fx_quote").is_none());
    }
    for query in ["limit=0","limit=101","limit=not_a_number","after=../../health"] {
        let response=client.get(format!("{base}/v1/corridors/page?{query}"))
            .send().await.expect("malformed request");
        assert_eq!(response.status(),reqwest::StatusCode::BAD_REQUEST, "{query}");
    }
    let missing=client.get(format!("{base}/v1/corridors/{}",Uuid::new_v4()))
        .send().await.expect("missing UUID");
    assert_eq!(missing.status(),reqwest::StatusCode::NOT_FOUND);

    server.abort();
    for id in fixtures {
        sqlx::query("DELETE FROM corridors WHERE id=$1").bind(id)
            .execute(&pool).await.expect("fixture cleanup");
    }
}
