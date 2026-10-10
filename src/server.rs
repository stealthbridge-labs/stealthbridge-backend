use axum::{
    body::{to_bytes,Body},
    extract::{Path, Query, State}, http::{header,HeaderValue,Request,StatusCode},
    middleware::{from_fn,Next}, response::Response, routing::{get, post}, Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::{env, error::Error, sync::{atomic::{AtomicBool,AtomicU64,Ordering},Arc}, time::{Duration,Instant,SystemTime,UNIX_EPOCH}};
use tokio::sync::Semaphore;
use tracing::warn;
use uuid::Uuid;
use crate::transaction::{self,TransactionObservation};
use crate::ledger::{self, VerifiedHead, LedgerCheckpoint};

/// The only network accepted until privacy, compliance and security gates are satisfied.
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_IN_FLIGHT_RPC: usize = 16;

/// Refuse accidental plaintext PostgreSQL credentials over remote networks.
/// Loopback Postgres remains available for isolated local CI and development.
fn validate_database_transport(database_url: &str) -> Result<(), Box<dyn Error>> {
    let url = reqwest::Url::parse(database_url)
        .map_err(|_| "DATABASE_URL must be a valid PostgreSQL URL")?;
    if !["postgres", "postgresql"].contains(&url.scheme())
        || url.username().is_empty() || url.password().is_none()
    {
        return Err("DATABASE_URL must be a PostgreSQL connection URL with credentials".into());
    }
    let host = url.host_str().ok_or("DATABASE_URL must include a database host")?;
    let local = ["localhost", "127.0.0.1", "[::1]", "::1"].contains(&host);
    if !local {
        let modes: Vec<String> = url.query_pairs()
            .filter(|(key, _)| key == "sslmode")
            .map(|(_, value)| value.into_owned()).collect();
        if modes.len() != 1 || !["require", "verify-ca", "verify-full"].contains(&modes[0].as_str()) {
            return Err("Remote PostgreSQL requires exactly one secure sslmode".into());
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    http: Client,
    rpc_url: String,
    db: Option<PgPool>,
    rpc_permits: Arc<Semaphore>,
    metrics_token:Option<String>,
    metrics:Arc<ReadinessMetrics>,
}

struct ReadinessMetrics {
    rpc_probes_total:AtomicU64,
    rpc_probe_errors_total:AtomicU64,
    rpc_probe_latency_ms_sum:AtomicU64,
    ledger_age_seconds:AtomicU64,
    database_configured:AtomicBool,
    database_available:AtomicBool,
}
impl Default for ReadinessMetrics {
    fn default()->Self {
        Self {rpc_probes_total:AtomicU64::new(0),rpc_probe_errors_total:AtomicU64::new(0),
            rpc_probe_latency_ms_sum:AtomicU64::new(0),ledger_age_seconds:AtomicU64::new(u64::MAX),
            database_configured:AtomicBool::new(false),database_available:AtomicBool::new(false)}
    }
}

impl AppState {
    pub async fn from_env() -> Result<Self, Box<dyn Error>> {
        let rpc_url = env::var("STELLAR_RPC_URL")
            .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_owned());
        let url = reqwest::Url::parse(&rpc_url)?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some() {
            return Err("STELLAR_RPC_URL must be HTTPS with no credentials, query or fragment".into());
        }
        let http = Client::builder().timeout(Duration::from_secs(8)).build()?;
        let db = match env::var("DATABASE_URL") {
            Ok(database_url) if !database_url.is_empty() => {
                // Do not automatically apply migrations in the application process.
                // Keep liveness independent from database reachability; /ready
                // reports failed connections with a bounded query timeout.
                validate_database_transport(&database_url)?;
                Some(PgPoolOptions::new()
                    // Vercel may start multiple function instances: bound each pool to
                    // avoid exhausting a managed PostgreSQL connection budget.
                    .min_connections(0)
                    .max_connections(2)
                    .acquire_timeout(Duration::from_secs(3))
                    .idle_timeout(Duration::from_secs(60))
                    .connect_lazy(&database_url)?)
            }
            _ => None,
        };
        let metrics_token=env::var("STEALTHBRIDGE_METRICS_TOKEN").ok().filter(|value|!value.is_empty());
        Ok(Self {http,rpc_url,db,rpc_permits:Arc::new(Semaphore::new(MAX_IN_FLIGHT_RPC)),
            metrics_token,metrics:Arc::new(ReadinessMetrics::default())})
    }

    #[cfg(test)]
    pub fn without_db() -> Self {
        Self {
            http: Client::new(),
            rpc_url: "https://soroban-testnet.stellar.org".to_owned(),
            db: None,
            rpc_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_RPC)),
            metrics_token:None,
            metrics:Arc::new(ReadinessMetrics::default()),
        }
    }

    async fn rpc(&self, method: &str) -> Result<Value, ()> {
        self.rpc_with_params(method, None).await
    }

    async fn rpc_with_params(&self, method: &str, params: Option<Value>) -> Result<Value, ()> {
        // Backpressure is bounded: no unbounded simultaneous Stellar RPC calls.
        // Permit release is automatic, including after timeout/cancellation.
        let _permit = self.rpc_permits.acquire().await.map_err(|_| ())?;
        let mut response = self.http.post(&self.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":"stealthbridge-observer","method":method,"params":params.unwrap_or(json!({}))}))
            .send().await.map_err(|_| ())?;
        if !response.status().is_success() {return Err(());}
        if response.content_length().is_some_and(|len| len > MAX_RPC_BODY_BYTES as u64) {
            return Err(());
        }
        // Do not use response.json(): a broken RPC could return arbitrarily
        // large, untrusted XDR/event payloads before parsing even starts.
        let mut body = Vec::with_capacity(4096);
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if chunk.len() > MAX_RPC_BODY_BYTES - body.len() {return Err(());}
            body.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&body).map_err(|_| ())?;
        Self::checked_rpc_envelope(&payload)
    }

    fn checked_rpc_envelope(payload: &Value) -> Result<Value, ()> {
        if payload.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || payload.get("id").and_then(Value::as_str) != Some("stealthbridge-observer")
            || payload.get("error").is_some_and(|value| !value.is_null()) {
            return Err(());
        }
        payload.get("result").filter(|value| !value.is_null()).cloned().ok_or(())
    }

    async fn network(&self) -> Result<NetworkStatus, ()> {
        let network = self.rpc("getNetwork").await?;
        let actual_passphrase = network.get("passphrase").and_then(Value::as_str).ok_or(())?;
        if actual_passphrase != TESTNET_PASSPHRASE {
            warn!("Configured Stellar RPC did not identify as testnet");
            return Err(());
        }
        let latest = self.rpc("getLatestLedger").await?;
        Ok(NetworkStatus {
            network: "testnet",
            passphrase: actual_passphrase.to_owned(),
            protocol_version: latest.get("protocolVersion").and_then(Value::as_u64).ok_or(())?,
            ledger_sequence: latest.get("sequence").and_then(Value::as_u64).ok_or(())?,
            ledger_closed_at_unix: latest.get("closeTime").and_then(Value::as_str).ok_or(())?.to_owned(),
            ledger_hash: {
                let hash = latest.get("id").and_then(Value::as_str).ok_or(())?;
                if !transaction::valid_hash(hash) { return Err(()); }
                hash.to_ascii_lowercase()
            },
            source: "stellar-rpc",
        })
    }
}

#[derive(Serialize)]
pub struct NetworkStatus {
    network: &'static str,
    passphrase: String,
    protocol_version: u64,
    ledger_sequence: u64,
    ledger_closed_at_unix: String,
    ledger_hash: String,
    source: &'static str,
}

#[derive(Serialize)]
pub struct Capabilities {
    payments_enabled: bool,
    confidential_token_verified: bool,
    private_payments_verified: bool,
    fiat_payouts_enabled: bool,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize, FromRow)]
pub struct Corridor {
    id: Uuid,
    origin_country: String,
    destination_country: String,
    asset_code: String,
    asset_issuer: Option<String>,
    privacy_rail: String,
}

/// This endpoint is not evidence of chain connectivity; /v1/network verifies live RPC.
async fn health() -> Json<Health> {
    Json(Health {status:"ok", service:"stealthbridge-backend"})
}
async fn network(State(state): State<Arc<AppState>>) -> Result<Json<NetworkStatus>, StatusCode> {
    state.network().await.map(Json).map_err(|_| StatusCode::BAD_GATEWAY)
}

/// Immutable build-time snapshot from stealthbridge-contracts/deployments/testnet.
/// Manifest VERIFIED does NOT equal independent on-chain verification.
const CONTRACT_MANIFEST: &str = include_str!("../deployments/testnet/manifest.json");
const CONTRACT_INTERFACE: &str = include_str!("../deployments/testnet/public-soroban-interface.v1.json");
#[derive(Serialize)]
struct ContractDiscovery {
    network: &'static str,
    source: &'static str,
    manifest: Value,
    public_interface: Value,
    on_chain_verified: bool,
    payment_execution_enabled: bool,
}
async fn contract_discovery() -> Result<Json<ContractDiscovery>,StatusCode> {
    let manifest:Value=serde_json::from_str(CONTRACT_MANIFEST)
        .map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    if manifest.get("schemaVersion").and_then(Value::as_u64)!=Some(1)
        || manifest.get("network").and_then(Value::as_str)!=Some("testnet")
        || manifest.get("status").and_then(Value::as_str)!=Some("not-deployed")
        || manifest.get("verified").and_then(Value::as_bool)!=Some(false)
        || manifest.get("contractAddresses").and_then(Value::as_object)
            .is_none_or(|addresses|!addresses.is_empty())
        || manifest.get("txHashes").and_then(Value::as_array)
            .is_none_or(|hashes|!hashes.is_empty())
    {
        // Never serve a future claimed deployment until a separate on-chain
        // attestation workflow is implemented and reviewed.
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let public_interface:Value=serde_json::from_str(CONTRACT_INTERFACE)
        .map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    if public_interface.get("schemaVersion").and_then(Value::as_u64)!=Some(1)
        || public_interface.get("network").and_then(Value::as_str)!=Some("testnet")
        || public_interface.get("status").and_then(Value::as_str)!=Some("source-interface-only")
    { return Err(StatusCode::SERVICE_UNAVAILABLE); }
    Ok(Json(ContractDiscovery{
        network:"testnet",
        source:"stealthbridge-contracts/deployments/testnet/manifest.json",
        manifest,
        public_interface,
        on_chain_verified:false,
        payment_execution_enabled:false,
    }))
}

async fn capabilities() -> Json<Capabilities> {
    // No real payment handlers or privacy verifications have been implemented.
    // These flags remain false until code and independently reproducible evidence exist.
    Json(Capabilities{
        payments_enabled:false,
        confidential_token_verified:false,
        private_payments_verified:false,
        fiat_payouts_enabled:false,
    })
}
async fn corridors(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Corridor>>, StatusCode> {
    let pool = state.db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let rows = sqlx::query_as::<_, Corridor>(
        "SELECT id, origin_country, destination_country, asset_code, asset_issuer, privacy_rail \
         FROM corridors WHERE enabled = TRUE ORDER BY origin_country, destination_country, id"
    ).fetch_all(pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct CorridorPageParams {
    after: Option<Uuid>,
    limit: Option<u32>,
}
#[derive(Serialize)]
struct CorridorPage {
    items: Vec<Corridor>,
    next_cursor: Option<Uuid>,
}
/// Keyset pagination by immutable corridor UUID. Never synthesize data or
/// paginate over unbounded client-provided counts.
async fn corridor_page(
    State(state): State<Arc<AppState>>, Query(params): Query<CorridorPageParams>,
) -> Result<Json<CorridorPage>, StatusCode> {
    let limit = params.limit.unwrap_or(25);
    if !(1..=100).contains(&limit) { return Err(StatusCode::BAD_REQUEST); }
    let pool = state.db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let mut rows = sqlx::query_as::<_, Corridor>(
        "SELECT id, origin_country, destination_country, asset_code, asset_issuer, privacy_rail \
         FROM corridors WHERE enabled = TRUE AND ($1::uuid IS NULL OR id > $1) \
         ORDER BY id LIMIT $2"
    )
    .bind(params.after).bind(i64::from(limit) + 1)
    .fetch_all(pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = if has_more {rows.last().map(|row| row.id)} else {None};
    Ok(Json(CorridorPage{items:rows,next_cursor}))
}

/// Read exactly one operator-configured, enabled corridor. Never invent entries.
async fn corridor_by_id(
    Path(id):Path<String>,State(state):State<Arc<AppState>>
)->Result<Json<Corridor>,StatusCode>{
    let id=Uuid::parse_str(&id).map_err(|_|StatusCode::BAD_REQUEST)?;
    let pool=state.db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    sqlx::query_as::<_,Corridor>(
        "SELECT id, origin_country, destination_country, asset_code, asset_issuer, privacy_rail \
         FROM corridors WHERE enabled=TRUE AND id=$1"
    ).bind(id).fetch_optional(pool).await
        .map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?
        .map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}
async fn disabled() -> (StatusCode, Json<ApiError>) {
    (StatusCode::NOT_IMPLEMENTED, Json(ApiError {
        code:"NOT_AVAILABLE",
        message:"Confidential settlement is not enabled. No transaction was submitted.",
    }))
}


async fn public_transaction(
    Path(hash): Path<String>, State(state): State<Arc<AppState>>,
) -> Result<Json<TransactionObservation>, StatusCode> {
    if !transaction::valid_hash(&hash) { return Err(StatusCode::BAD_REQUEST); }
    // Fail closed against accidentally pointing a deployment at another network.
    let network = state.rpc("getNetwork").await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    if network.get("passphrase").and_then(Value::as_str) != Some(TESTNET_PASSPHRASE) {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let result = state.rpc_with_params("getTransaction", Some(json!({"hash":hash.to_ascii_lowercase()})))
        .await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    transaction::parse_result(&hash,&result)
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .map(Json).ok_or(StatusCode::NOT_FOUND)
}


/// Public metadata-only view of the last operator-enabled observer checkpoint.
/// This says nothing about a user payment, note privacy or provider payout.
async fn observer_head(
    State(state):State<Arc<AppState>>,
)->Result<Json<LedgerCheckpoint>,StatusCode>{
    let pool=state.db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    ledger::last_head(pool).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?
        .map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// Must be enabled explicitly with STEALTHBRIDGE_ENABLE_LEDGER_OBSERVER=true.
/// Run one designated observer per environment to avoid redundant RPC polling.
pub async fn run_ledger_observer(state:AppState) {
    let Some(pool)=state.db.clone() else {
        warn!("Ledger observer requested but PostgreSQL is not configured");
        return;
    };
    let mut interval=tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match state.network().await {
            Ok(status)=>{
                let head=VerifiedHead{
                    passphrase:status.passphrase,
                    ledger_sequence:status.ledger_sequence,
                    ledger_hash:status.ledger_hash,
                    ledger_closed_at_unix:status.ledger_closed_at_unix,
                };
                if let Err(error)=ledger::record_head(&pool,&head).await {
                    warn!(error=?error,"Ledger checkpoint rejected or storage unavailable");
                }
            }
            Err(_)=>warn!("Stellar Testnet observer could not verify upstream RPC"),
        }
    }
}

/// Ledger heads are freshness-bound independently of RPC HTTP liveness.
/// A small future-clock allowance tolerates upstream timestamp/clock skew.
fn ledger_is_fresh(closed_at_unix:&str, now:u64, max_age_secs:u64)->bool {
    closed_at_unix.parse::<u64>().is_ok_and(|closed_at| {
        closed_at <= now.saturating_add(30) &&
        now.saturating_sub(closed_at) <= max_age_secs
    })
}

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    stellar_rpc: &'static str,
    database: &'static str,
    payments: &'static str,
}
fn readiness_projection(chain:bool,db_configured:bool,db_available:bool)->Readiness{
    let database=if !db_configured{"not-configured"}else if db_available{"connected"}else{"unavailable"};
    let ready=chain&&database=="connected";
    Readiness{status:if ready{"ready"}else{"degraded"},
        stellar_rpc:if chain{"connected"}else{"unavailable"},database,payments:"disabled"}
}
/// Non-custodial readiness observation: healthy process != usable payment rail.
async fn readiness(State(state):State<Arc<AppState>>)
    ->(StatusCode,Json<Readiness>){
    // Parallel bounded checks reduce the load balancer's worst-case wait.
    let rpc_probe=async {
        let started=Instant::now();
        let result=state.network().await;
        (result,started.elapsed())
    };
    let ((chain_result,rpc_latency), db_result) = tokio::join!(
        rpc_probe,
        async {
            match &state.db {
                Some(pool) => tokio::time::timeout(
                    Duration::from_secs(2),
                    sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool)
                ).await.is_ok_and(|result| result.is_ok()),
                None => false,
            }
        }
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs()).unwrap_or(0);
    // A responsive RPC with an old ledger is not a healthy observer.
    let ledger_age=chain_result.as_ref().ok().and_then(|head|head.ledger_closed_at_unix.parse::<u64>().ok())
        .filter(|closed_at|*closed_at<=now.saturating_add(30)).map(|closed_at|now.saturating_sub(closed_at));
    let chain = chain_result.is_ok_and(|head| ledger_is_fresh(&head.ledger_closed_at_unix, now, 180));
    let db_configured=state.db.is_some();
    state.metrics.rpc_probes_total.fetch_add(1,Ordering::Relaxed);
    if !chain {state.metrics.rpc_probe_errors_total.fetch_add(1,Ordering::Relaxed);}
    state.metrics.rpc_probe_latency_ms_sum.fetch_add(rpc_latency.as_millis().min(u64::MAX as u128) as u64,Ordering::Relaxed);
    state.metrics.ledger_age_seconds.store(ledger_age.unwrap_or(u64::MAX),Ordering::Relaxed);
    state.metrics.database_configured.store(db_configured,Ordering::Relaxed);
    state.metrics.database_available.store(db_result,Ordering::Relaxed);
    let result=readiness_projection(chain,db_configured,db_result);
    let status=if result.status=="ready"{StatusCode::OK}else{StatusCode::SERVICE_UNAVAILABLE};
    (status,Json(result))
}

fn safe_error(status:StatusCode)->(&'static str,&'static str){
    match status{
        StatusCode::BAD_REQUEST=>("INVALID_REQUEST","The request parameters are invalid."),
        StatusCode::UNAUTHORIZED|StatusCode::FORBIDDEN=>("UNAUTHORIZED","The request is not authorized."),
        StatusCode::NOT_FOUND=>("NOT_FOUND","The requested resource was not found."),
        StatusCode::TOO_MANY_REQUESTS=>("RATE_LIMITED","Too many requests. Retry after a short delay."),
        StatusCode::BAD_GATEWAY=>("UPSTREAM_UNAVAILABLE","The upstream service returned an invalid or unavailable response."),
        StatusCode::SERVICE_UNAVAILABLE=>("DEPENDENCY_UNAVAILABLE","A required service is unavailable or not configured."),
        StatusCode::NOT_IMPLEMENTED=>("FEATURE_DISABLED","This operation is not enabled. No transaction was submitted."),
        _=>("REQUEST_FAILED","The request could not be completed."),
    }
}
#[derive(Serialize)]
struct ErrorDetails {code:&'static str,message:&'static str}
#[derive(Serialize)]
struct ErrorEnvelope {error:ErrorDetails,trace_id:String,#[serde(skip_serializing_if="Option::is_none")]details:Option<Value>}

async fn diagnostic_responses(request:Request<Body>,next:Next)->Response{
    let path=request.uri().path().to_owned();
    let response=next.run(request).await;
    let trace_id=Uuid::new_v4().to_string();
    let status=response.status();
    let (mut parts,body)=response.into_parts();
    let response=if status.is_client_error()||status.is_server_error(){
        let details=if path=="/ready"&&status==StatusCode::SERVICE_UNAVAILABLE{
            to_bytes(body,64*1024).await.ok().and_then(|bytes|serde_json::from_slice(&bytes).ok())
        }else{None};
        let (code,message)=safe_error(status);
        let envelope=ErrorEnvelope{error:ErrorDetails{code,message},trace_id:trace_id.clone(),details};
        let payload=serde_json::to_vec(&envelope).unwrap_or_else(|_|b"{}".to_vec());
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::CONTENT_ENCODING);
        parts.headers.insert(header::CONTENT_TYPE,HeaderValue::from_static("application/json"));
        parts.headers.insert("x-error-code",HeaderValue::from_static(code));
        warn!(trace_id=%trace_id,status=status.as_u16(),"Public API request failed");
        Response::from_parts(parts,Body::from(payload))
    }else{Response::from_parts(parts,body)};
    let mut response=response;
    response.headers_mut().insert("x-request-id",HeaderValue::from_str(&trace_id).expect("UUID is a valid header value"));
    response
}

fn token_matches(expected:&str,provided:&str)->bool{
    if expected.len()!=provided.len(){return false;}
    expected.bytes().zip(provided.bytes()).fold(0u8,|difference,(left,right)|difference|(left^right))==0
}
async fn internal_metrics(State(state):State<Arc<AppState>>,headers:axum::http::HeaderMap)
    ->Result<(StatusCode,[(header::HeaderName,HeaderValue);1],String),StatusCode>{
    let token=state.metrics_token.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let supplied=headers.get(header::AUTHORIZATION).and_then(|value|value.to_str().ok())
        .and_then(|value|value.strip_prefix("Bearer ")).ok_or(StatusCode::UNAUTHORIZED)?;
    if !token_matches(token,supplied){return Err(StatusCode::UNAUTHORIZED);}
    let metrics=&state.metrics;
    let age=metrics.ledger_age_seconds.load(Ordering::Relaxed);
    let age_line=if age==u64::MAX{String::new()}else{format!("stealthbridge_observed_ledger_age_seconds {age}\n")};
    let db_configured=u8::from(metrics.database_configured.load(Ordering::Relaxed));
    let db_available=u8::from(metrics.database_available.load(Ordering::Relaxed));
    let body=format!("# HELP stealthbridge_readiness_rpc_probes_total Readiness RPC probes.\n# TYPE stealthbridge_readiness_rpc_probes_total counter\nstealthbridge_readiness_rpc_probes_total {}\n# HELP stealthbridge_readiness_rpc_probe_errors_total Failed readiness RPC probes.\n# TYPE stealthbridge_readiness_rpc_probe_errors_total counter\nstealthbridge_readiness_rpc_probe_errors_total {}\n# HELP stealthbridge_readiness_rpc_probe_latency_ms_sum Cumulative readiness RPC probe latency in milliseconds.\n# TYPE stealthbridge_readiness_rpc_probe_latency_ms_sum counter\nstealthbridge_readiness_rpc_probe_latency_ms_sum {}\n# HELP stealthbridge_database_configured Whether PostgreSQL is configured.\n# TYPE stealthbridge_database_configured gauge\nstealthbridge_database_configured {db_configured}\n# HELP stealthbridge_database_available Whether configured PostgreSQL is reachable.\n# TYPE stealthbridge_database_available gauge\nstealthbridge_database_available {db_available}\n# HELP stealthbridge_observed_ledger_age_seconds Age of the latest verified Testnet ledger head.\n# TYPE stealthbridge_observed_ledger_age_seconds gauge\n{age_line}# HELP stealthbridge_journal_transitions_total Public journal transitions; no public transition API is enabled.\n# TYPE stealthbridge_journal_transitions_total counter\nstealthbridge_journal_transitions_total 0\n",
        metrics.rpc_probes_total.load(Ordering::Relaxed),metrics.rpc_probe_errors_total.load(Ordering::Relaxed),
        metrics.rpc_probe_latency_ms_sum.load(Ordering::Relaxed));
    Ok((StatusCode::OK,[(header::CONTENT_TYPE,HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"))],body))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health",get(health))
        .route("/ready",get(readiness))
        .route("/internal/metrics",get(internal_metrics))
        .route("/v1/network",get(network))
        .route("/v1/observer",get(observer_head))
        .route("/v1/capabilities",get(capabilities))
        .route("/v1/contracts",get(contract_discovery))
        .route("/v1/corridors",get(corridors))
        .route("/v1/corridors/page",get(corridor_page))
        .route("/v1/corridors/{id}",get(corridor_by_id))
        .route("/v1/transactions/{hash}",get(public_transaction))
        .route("/v1/settlements",post(disabled))
        .layer(from_fn(diagnostic_responses))
        .with_state(Arc::new(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_postgres_requires_tls_and_local_ci_remains_supported() {
        assert!(validate_database_transport("postgres://ci:ci@localhost:5432/ci").is_ok());
        assert!(validate_database_transport("postgresql://ci:ci@127.0.0.1/ci").is_ok());
        assert!(validate_database_transport("postgresql://user:pass@db.example/neondb?channel_binding=require&sslmode=require").is_ok());
        assert!(validate_database_transport("postgresql://user:pass@db.example/neondb?sslmode=verify-full").is_ok());
        for rejected in [
            "postgresql://user:pass@db.example/neondb",
            "postgresql://user:pass@db.example/neondb?sslmode=disable",
            "postgresql://user:pass@db.example/neondb?sslmode=prefer",
            "postgresql://user:pass@db.example/neondb?sslmode=require&sslmode=disable",
            "http://user:pass@db.example/neondb?sslmode=require",
        ] {
            assert!(validate_database_transport(rejected).is_err());
        }
    }
    #[test]
    fn readiness_distinguishes_missing_and_unavailable_database_states(){
        let missing=readiness_projection(true,false,false);
        assert_eq!(missing.status,"degraded");
        assert_eq!(missing.database,"not-configured");
        assert_eq!(missing.payments,"disabled");
        let unavailable=readiness_projection(true,true,false);
        assert_eq!(unavailable.database,"unavailable");
        assert_eq!(unavailable.status,"degraded");
        let rpc_down=readiness_projection(false,true,true);
        assert_eq!(rpc_down.stellar_rpc,"unavailable");
        assert_eq!(rpc_down.status,"degraded");
        assert_eq!(readiness_projection(true,true,true).status,"ready");
    }
    #[test]
    fn public_error_codes_and_metrics_auth_are_stable(){
        assert_eq!(safe_error(StatusCode::TOO_MANY_REQUESTS).0,"RATE_LIMITED");
        assert_eq!(safe_error(StatusCode::BAD_GATEWAY).0,"UPSTREAM_UNAVAILABLE");
        assert_eq!(safe_error(StatusCode::SERVICE_UNAVAILABLE).0,"DEPENDENCY_UNAVAILABLE");
        assert!(token_matches("internal-secret","internal-secret"));
        assert!(!token_matches("internal-secret","internal-secret-extra"));
        assert!(!token_matches("internal-secret","public"));
    }
    #[tokio::test]
    async fn contract_discovery_reflects_actual_undeployed_canonical_manifest() {
        let response=contract_discovery().await.expect("synchronized Testnet manifest");
        assert_eq!(response.0.network,"testnet");
        assert!(!response.0.on_chain_verified);
        assert!(!response.0.payment_execution_enabled);
        assert_eq!(response.0.manifest["status"],"not-deployed");
        assert_eq!(response.0.public_interface["status"],"source-interface-only");
        assert!(response.0.public_interface["contracts"]["corridor-registry"]["reads"]["is_enabled"].is_object());
        assert!(response.0.manifest["contractAddresses"].as_object()
            .is_some_and(|entries|entries.is_empty()));
    }
    #[test]
    fn router_constructs_without_database_or_credentials() {
        let _ = router(AppState::without_db());
    }
    #[test]
    fn testnet_network_passphrase_is_explicit() {
        assert_eq!(TESTNET_PASSPHRASE, "Test SDF Network ; September 2015");
    }
    #[test]
    fn upstream_must_have_matching_rpc_envelope_and_no_error() {
        let valid = json!({"jsonrpc":"2.0","id":"stealthbridge-observer","result":{"status":"NOT_FOUND"}});
        assert_eq!(AppState::checked_rpc_envelope(&valid).unwrap()["status"],"NOT_FOUND");
        for broken in [
            json!({"id":"stealthbridge-observer","result":{}}),
            json!({"jsonrpc":"2.0","id":"another-client","result":{}}),
            json!({"jsonrpc":"2.0","id":"stealthbridge-observer","result":null}),
            json!({"jsonrpc":"2.0","id":"stealthbridge-observer","error":{"code":-32000}}),
        ] { assert!(AppState::checked_rpc_envelope(&broken).is_err()); }
    }
    #[test]
    fn stale_and_future_dated_heads_make_readiness_degraded() {
        assert!(ledger_is_fresh("1760000000", 1760000010, 180));
        assert!(!ledger_is_fresh("1759999000", 1760000010, 180));
        assert!(!ledger_is_fresh("1760000100", 1760000010, 180));
        assert!(!ledger_is_fresh("not-a-timestamp", 1760000010, 180));
        assert!(!ledger_is_fresh("", 1760000010, 180));
        assert!(ledger_is_fresh("1760000030", 1760000010, 180));
    }
    #[test]
    fn backpressure_and_response_budget_are_finite() {
        assert_eq!(MAX_IN_FLIGHT_RPC,16);
        assert_eq!(MAX_RPC_BODY_BYTES,2*1024*1024);
    }
}
