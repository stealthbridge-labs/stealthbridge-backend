//! Stateless Vercel Rust Function adapter for the existing Axum router.
//! Does not run the persistent ledger observer (serverless has no worker lease).
use tower::ServiceBuilder;
use vercel_runtime::{axum::VercelLayer,Error};
use axum::{http::StatusCode,Json,Router};

#[tokio::main]
async fn main()->Result<(),Error>{
    // A configuration failure must never cause Vercel to replace our response
    // with an opaque 500 crash. Return a safe 503 instead, without revealing
    // database credentials, RPC paths, auth secrets or other environment data.
    // Health is deliberately NOT reported healthy in this degraded mode.
    let app: Router=match stealthbridge_backend::server::AppState::from_env().await{
        Ok(state)=>stealthbridge_backend::server::router(state),
        Err(error)=>{
            let description=error.to_string();
            let code=if description.contains("DATABASE_URL") ||
                description.contains("PostgreSQL") {
                "INVALID_DATABASE_CONFIGURATION"
            }else if description.contains("STELLAR_RPC_URL"){
                "INVALID_STELLAR_RPC_CONFIGURATION"
            }else if description.contains("auth") ||
                description.contains("SESSION_SECRET"){
                "INVALID_AUTH_CONFIGURATION"
            }else{
                "BACKEND_BOOTSTRAP_UNAVAILABLE"
            };
            eprintln!("StealthBridge: safe backend startup failure category: {code}");
            Router::new().fallback(move || async move {
                (StatusCode::SERVICE_UNAVAILABLE,
                 Json(serde_json::json!({
                    "code":code,"status":"unavailable",
                    "payment_execution_enabled":false,
                    "fee_collection_enabled":false,
                    "message":"The backend service configuration is unavailable."
                 })))
            })
        }
    };
    let app=ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(app);
    vercel_runtime::run(app).await
}
