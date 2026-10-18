//! Minimal read-only Vercel Rust runtime probe.
//! Does not load configuration, touch PostgreSQL or send an RPC request.
//! Helps distinguish a platform/runtime invocation failure from Axum startup.
use serde_json::{json,Value};
use vercel_runtime::{run,service_fn,Error,Request};

#[tokio::main]
async fn main()->Result<(),Error>{
    run(service_fn(probe)).await
}

async fn probe(_request:Request)->Result<Value,Error>{
    Ok(json!({
        "service":"stealthbridge-rust-runtime",
        "runtime_responding":true,
        "backend_ready":false,
        "payment_execution_enabled":false,
        "fee_collection_enabled":false
    }))
}
