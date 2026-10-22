//! Voluntary pending business registration backed by EXISTING Neon tenant tables.
//! No business approval, compliance verification, fee claims or settlement writes.
//! A verified Next.js session signs method/path/account/timestamp/request ID/body.
use crate::{server::AppState,wallet};
use axum::{
 body::Bytes,extract::State,http::{header,HeaderMap,HeaderValue,StatusCode},
 response::{IntoResponse,Response},Json
};
use hmac::{Hmac,Mac};
use serde::{Deserialize,Serialize};
use sha2::{Sha256,Digest};
use sqlx::{PgPool,Row};
use std::{sync::Arc,time::{Duration,SystemTime,UNIX_EPOCH}};
use uuid::Uuid;

type AuthMac=Hmac<Sha256>;
const PATH:&str="/v1/account/business-onboarding";
const DOMAIN:&str="stealthbridge-business-onboarding-v1";
const MAX_PENDING:i64=3;
const MAX_RESULTS:i64=10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationInput{display_name:String}
impl ApplicationInput{
 fn valid(&self)->bool{
  let v=&self.display_name;
  !v.is_empty()&&v.len()<=120&&v.trim()==v&&
  !v.chars().any(|c|c.is_control()||c=='<'||c=='>')
 }
}
#[derive(Serialize)]
struct PendingBusiness{ id:Uuid,display_name:String,status:&'static str,role:&'static str }
#[derive(Serialize)]
struct OnboardingResult{
 schema_version:u8,network:&'static str,source:&'static str,account_address:String,
 applications:Vec<PendingBusiness>,has_more:bool,
 organization_verified:bool,payment_execution_enabled:bool,organization_payment_authorized:bool
}
fn response_for(account:String,applications:Vec<PendingBusiness>,has_more:bool)->OnboardingResult{
 OnboardingResult{schema_version:1,network:"testnet",source:"neon-pending-business-applications",
  account_address:account,applications,has_more,
  organization_verified:false,payment_execution_enabled:false,organization_payment_authorized:false}
}
fn now_unix()->i64{
 SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs() as i64).unwrap_or(0)
}
fn verify_request(
 headers:&HeaderMap,secret:Option<&[u8]>,method:&str,request_id:&str,digest:&str,now:i64
)->Option<String>{
 let secret=secret.filter(|s|s.len()>=32)?;
 let address=headers.get("x-stealthbridge-account")?.to_str().ok()?;
 wallet::decode_account_address(address)?;
 let timestamp=headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
 if timestamp.is_empty()||timestamp.len()>12||
    !timestamp.bytes().all(|b|b.is_ascii_digit()){return None;}
 let issued=timestamp.parse::<i64>().ok()?;
 if issued<=0||issued>now+5||now.saturating_sub(issued)>30{return None;}
 let signature=headers.get("x-stealthbridge-signature")?.to_str().ok()?;
 if signature.len()!=64||!signature.bytes().all(|b|b.is_ascii_hexdigit()){return None;}
 let raw=hex::decode(signature).ok()?;
 let signed=format!("{DOMAIN}\n{method}\n{PATH}\n{address}\n{timestamp}\n{request_id}\n{digest}\n");
 let mut mac=AuthMac::new_from_slice(secret).ok()?;
 mac.update(signed.as_bytes());
 mac.verify_slice(&raw).ok()?;
 Some(address.to_string())
}
fn signing_key(state:&AppState)->Option<&[u8]>{
 state.account_bridge_secret.as_ref().map(|x|x.as_slice())
}
async fn list_pending(pool:&PgPool,account:&str)->Result<(Vec<PendingBusiness>,bool),sqlx::Error>{
 let rows=sqlx::query(
  r#"SELECT o.id,o.display_name FROM organizations o
   JOIN organization_members m ON m.organization_id=o.id
   WHERE m.subject=$1 AND m.role='owner' AND m.revoked_at IS NULL
     AND o.status='pending'
   ORDER BY o.created_at DESC,o.id DESC LIMIT 11"#
 ).bind(account).fetch_all(pool).await?;
 let has_more=rows.len() as i64>MAX_RESULTS;
 let mut applications=Vec::with_capacity(rows.len().min(MAX_RESULTS as usize));
 for row in rows.into_iter().take(MAX_RESULTS as usize){
  applications.push(PendingBusiness{
   id:row.try_get("id")?,display_name:row.try_get("display_name")?,
   status:"pending",role:"owner"
  });
 }
 Ok((applications,has_more))
}
pub async fn list_business_applications(
 State(state):State<Arc<AppState>>,headers:HeaderMap
)->Response{
 let Some(secret)=signing_key(&state) else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 let Some(account)=verify_request(&headers,Some(secret),"GET","","",now_unix()) else{
  return StatusCode::UNAUTHORIZED.into_response();
 };
 let Some(pool)=state.db.as_ref() else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 match tokio::time::timeout(Duration::from_secs(4),list_pending(pool,&account)).await{
  Ok(Ok((items,has_more)))=>([
   (header::CACHE_CONTROL,HeaderValue::from_static("private, no-store"))
  ],Json(response_for(account,items,has_more))).into_response(),
  _=>StatusCode::SERVICE_UNAVAILABLE.into_response()
 }
}
#[derive(Debug)]
enum CreateError{Limit,Replay,Database(sqlx::Error)}
impl From<sqlx::Error> for CreateError{
 fn from(e:sqlx::Error)->Self{Self::Database(e)}
}
async fn create_pending(
 pool:&PgPool,account:&str,id:Uuid,display_name:&str
)->Result<PendingBusiness,CreateError>{
 let mut transaction=pool.begin().await?;
 // Serializes applications from the SAME wallet, including concurrent
 // Vercel functions, so the 3-pending cap cannot be raced.
 sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,731))")
  .bind(account).execute(&mut *transaction).await?;
 let number:i64=sqlx::query_scalar(
  r#"SELECT COUNT(*) FROM organizations o
   JOIN organization_members m ON m.organization_id=o.id
   WHERE m.subject=$1 AND m.role='owner' AND m.revoked_at IS NULL
    AND o.status='pending'"#
 ).bind(account).fetch_one(&mut *transaction).await?;
 // UUID is both the exact signed idempotency nonce and organization primary key.
 // Never return or elevate another user's application when IDs collide.
 if sqlx::query_scalar::<_,bool>(
  "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)"
 ).bind(id).fetch_one(&mut *transaction).await?{
  return Err(CreateError::Replay);
 }
 if number>=MAX_PENDING{return Err(CreateError::Limit);}
 sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES($1,$2,'pending')")
  .bind(id).bind(display_name).execute(&mut *transaction).await?;
 sqlx::query(
  "INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,'owner')"
 ).bind(id).bind(account).execute(&mut *transaction).await?;
 transaction.commit().await?;
 Ok(PendingBusiness{id,display_name:display_name.to_string(),status:"pending",role:"owner"})
}
pub async fn create_business_application(
 State(state):State<Arc<AppState>>,headers:HeaderMap,body:Bytes
)->Response{
 let Some(secret)=signing_key(&state) else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 if body.len()>512||body.is_empty(){return StatusCode::BAD_REQUEST.into_response();}
 let Some(id)=headers.get("x-stealthbridge-request-id")
  .and_then(|v|v.to_str().ok())
  .and_then(|v|Uuid::parse_str(v).ok())
  .filter(|id|!id.is_nil()) else {return StatusCode::UNAUTHORIZED.into_response();};
 let digest=hex::encode(Sha256::digest(&body));
 let Some(account)=verify_request(&headers,Some(secret),"POST",&id.to_string(),&digest,now_unix()) else {
  return StatusCode::UNAUTHORIZED.into_response();
 };
 let Ok(input)=serde_json::from_slice::<ApplicationInput>(&body) else{
  return StatusCode::BAD_REQUEST.into_response();
 };
 if !input.valid(){return StatusCode::BAD_REQUEST.into_response();}
 let Some(pool)=state.db.as_ref() else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 match tokio::time::timeout(Duration::from_secs(5),create_pending(pool,&account,id,&input.display_name)).await{
  Ok(Ok(record))=>(StatusCode::CREATED,
   [(header::CACHE_CONTROL,HeaderValue::from_static("private, no-store"))],
   Json(response_for(account,vec![record],false))).into_response(),
  Ok(Err(CreateError::Limit))=>StatusCode::TOO_MANY_REQUESTS.into_response(),
  Ok(Err(CreateError::Replay))=>StatusCode::CONFLICT.into_response(),
  Ok(Err(CreateError::Database(error)))=>{
   tracing::warn!(error=%error,"business application database unavailable");
   StatusCode::SERVICE_UNAVAILABLE.into_response()
  }
  _=>StatusCode::SERVICE_UNAVAILABLE.into_response()
 }
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]
 fn request_signature_is_bound_to_real_method_account_nonce_and_body(){
  let secret=b"CI-only-integration-HMAC-1234567890123456789";
  let account="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
  let now=1_800_000_000_i64;
  let stamp=now.to_string();
  let nonce=Uuid::new_v4().to_string();
  let digest="a".repeat(64);
  let content=format!("{DOMAIN}\nPOST\n{PATH}\n{account}\n{stamp}\n{nonce}\n{digest}\n");
  let mut mac=AuthMac::new_from_slice(secret).unwrap();
  mac.update(content.as_bytes());
  let signature=hex::encode(mac.finalize().into_bytes());
  let mut headers=HeaderMap::new();
  headers.insert("x-stealthbridge-account",HeaderValue::from_static(account));
  headers.insert("x-stealthbridge-issued-at",HeaderValue::from_str(&stamp).unwrap());
  headers.insert("x-stealthbridge-signature",HeaderValue::from_str(&signature).unwrap());
  assert_eq!(verify_request(&headers,Some(secret),"POST",&nonce,&digest,now),Some(account.into()));
  assert!(verify_request(&headers,Some(secret),"GET",&nonce,&digest,now).is_none());
  assert!(verify_request(&headers,Some(secret),"POST","different",&digest,now).is_none());
  assert!(verify_request(&headers,Some(secret),"POST",&nonce,"different",now).is_none());
  assert!(verify_request(&headers,Some(secret),"POST",&nonce,&digest,now+31).is_none());
  assert!(verify_request(&headers,None,"POST",&nonce,&digest,now).is_none());
 }
 #[tokio::test]
 async fn pending_registration_is_persisted_replay_safe_and_never_activates_payments(){
  let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL");
  let pool=PgPool::connect(&url).await.expect("CI db");
  sqlx::migrate!("./migrations").run(&pool).await.expect("schema");
  let account="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
  let orgs=sqlx::query_scalar::<_,Uuid>(
    "SELECT o.id FROM organizations o JOIN organization_members m ON m.organization_id=o.id
     WHERE m.subject=$1 AND o.display_name LIKE 'CI ONLY PENDING ONBOARDING %'")
     .bind(account).fetch_all(&pool).await.unwrap();
  assert!(orgs.is_empty(),"CI fixtures must be clean at test start");
  let ids:Vec<Uuid>=(0..3).map(|_|Uuid::new_v4()).collect();
  for (i,id) in ids.iter().enumerate(){
    let business=format!("CI ONLY PENDING ONBOARDING {i}");
    let entry=create_pending(&pool,account,*id,&business).await.expect("pending");
    assert_eq!(entry.status,"pending");
    assert_eq!(entry.role,"owner");
  }
  assert!(matches!(
   create_pending(&pool,account,ids[0],"CI ONLY DUPLICATE").await,
   Err(CreateError::Replay)
  ));
  assert!(matches!(
   create_pending(&pool,account,Uuid::new_v4(),"CI ONLY FOURTH").await,
   Err(CreateError::Limit)
  ));
  let (pending,more)=list_pending(&pool,account).await.unwrap();
  assert!(pending.iter().filter(|row|ids.contains(&row.id)).count()==3);
  assert!(!more);
  for id in ids{
   let status:String=sqlx::query_scalar("SELECT status FROM organizations WHERE id=$1")
     .bind(id).fetch_one(&pool).await.unwrap();
   assert_eq!(status,"pending");
   sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
     .bind(id).execute(&pool).await.unwrap();
   sqlx::query("DELETE FROM organizations WHERE id=$1")
     .bind(id).execute(&pool).await.unwrap();
  }
 }
 #[test]
 fn application_name_is_not_legal_verification(){
  assert!(ApplicationInput{display_name:"Independent importer".into()}.valid());
  for value in ["","  Untrimmed","<script>","a\nnewline"]{
   assert!(!ApplicationInput{display_name:value.into()}.valid());
  }
  assert!(!ApplicationInput{display_name:"a".repeat(121)}.valid());
  assert!(serde_json::from_str::<ApplicationInput>(
   r#"{"display_name":"Acme","kyc_verified":true}"#).is_err());
 }
}
