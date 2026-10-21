//! Optional customer-controlled, non-financial account profile.
//! A browser session is verified by the Next.js BFF; the BFF signs an exact
 //! method/path/account/timestamp/nonce/body-digest context for Rust. PostgreSQL
 //! one-use receipts prevent PATCH replay. No financial authorization.
use axum::{
 body::Bytes,extract::State,http::{header,HeaderMap,HeaderValue,StatusCode},
 response::{IntoResponse,Response},Json
};
use hmac::{Hmac,Mac};
use serde::{Deserialize,Serialize};
use serde_json::json;
use sha2::{Sha256,Digest};
use sqlx::{PgPool,Row};
use std::{sync::Arc,time::{Duration,SystemTime,UNIX_EPOCH}};
use uuid::Uuid;
use crate::{server::AppState,wallet};

type Mac256=Hmac<Sha256>;
const DOMAIN:&str="stealthbridge-customer-profile-v1";
const PATH:&str="/v1/account/profile";

#[derive(Clone,Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileChanges{
 display_name:String,
 use_case:String,
 residence_country:Option<String>,
}
impl ProfileChanges{
 fn valid(&self)->bool{
  let display=self.display_name.as_str();
  let len=display.chars().count();
  (1..=80).contains(&len)&&display.trim()==display&&
  !display.chars().any(|c|c.is_control()||c=='<'||c=='>')&&
  matches!(self.use_case.as_str(),"personal"|"business"|"both")&&
  self.residence_country.as_deref().is_none_or(|c|
   c.len()==2&&c.bytes().all(|b|b.is_ascii_uppercase()))
 }
}
#[derive(Serialize)]
struct ProfileRow{
 display_name:String,
 use_case:String,
 residence_country:Option<String>,
 updated_at_unix:i64,
}
#[derive(Serialize)]
struct ProfileResult{
 schema_version:u8,network:&'static str,source:&'static str,
 account_address:String,profile:Option<ProfileRow>,
 payment_execution_enabled:bool,organization_payment_authorized:bool,
}

fn now_unix()->i64{
 SystemTime::now().duration_since(UNIX_EPOCH)
  .map(|d|d.as_secs() as i64).unwrap_or(0)
}
fn account_for(
 headers:&HeaderMap,secret:Option<&[u8]>,method:&str,
 nonce:&str,body_sha256:&str,now:i64
)->Option<String>{
 let secret=secret.filter(|s|s.len()>=32)?;
 let account=headers.get("x-stealthbridge-account")?.to_str().ok()?;
 if wallet::decode_account_address(account).is_none(){return None;}
 let timestamp=headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
 if timestamp.len()>12||timestamp.is_empty()||
  !timestamp.bytes().all(|b|b.is_ascii_digit()){return None;}
 let when=timestamp.parse::<i64>().ok()?;
 if when<=0||when>now+5||now.saturating_sub(when)>30{return None;}
 let sig=headers.get("x-stealthbridge-signature")?.to_str().ok()?;
 if sig.len()!=64||!sig.bytes().all(|b|b.is_ascii_hexdigit()){return None;}
 let supplied=hex::decode(sig).ok()?;
 let content=format!("{DOMAIN}\n{method}\n{PATH}\n{account}\n{timestamp}\n{nonce}\n{body_sha256}\n");
 let mut mac=Mac256::new_from_slice(secret).ok()?;
 mac.update(content.as_bytes());
 mac.verify_slice(&supplied).ok()?;
 Some(account.to_owned())
}
fn secret(state:&AppState)->Option<&[u8]>{
 state.account_bridge_secret.as_ref().map(|x|x.as_slice())
}
fn row_value(row:sqlx::postgres::PgRow)->Result<ProfileRow,sqlx::Error>{
 Ok(ProfileRow{
  display_name:row.try_get("display_name")?,
  use_case:row.try_get("use_case")?,
  residence_country:row.try_get("residence_country")?,
  updated_at_unix:row.try_get("updated_at_unix")?,
 })
}
fn envelope(address:String,profile:Option<ProfileRow>)->ProfileResult{
 ProfileResult{schema_version:1,network:"testnet",source:"neon-customer-profiles",
  account_address:address,profile,
  payment_execution_enabled:false,organization_payment_authorized:false}
}
const SELECT_PROFILE:&str="SELECT display_name,use_case,residence_country,
 EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at_unix
 FROM customer_profiles WHERE account_address=$1";

pub async fn get_profile(State(state):State<Arc<AppState>>,headers:HeaderMap)->Response{
 let Some(secret)=secret(&state) else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 let Some(account)=account_for(&headers,Some(secret),"GET","","",now_unix()) else{
  return StatusCode::UNAUTHORIZED.into_response();
 };
 let Some(db)=state.db.as_ref() else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 let result=tokio::time::timeout(Duration::from_secs(4),
  sqlx::query(SELECT_PROFILE).bind(&account).fetch_optional(db)).await;
 match result{
  Ok(Ok(row))=>{
   let profile=match row.map(row_value).transpose(){
    Ok(p)=>p,Err(_)=>return StatusCode::SERVICE_UNAVAILABLE.into_response()
   };
   ([(header::CACHE_CONTROL,HeaderValue::from_static("private, no-store"))],
    Json(envelope(account,profile))).into_response()
  }
  _=>StatusCode::SERVICE_UNAVAILABLE.into_response()
 }
}
pub async fn patch_profile(
 State(state):State<Arc<AppState>>,headers:HeaderMap,body:Bytes
)->Response{
 let Some(secret)=secret(&state) else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 if body.is_empty()||body.len()>1024{return StatusCode::BAD_REQUEST.into_response();}
 let Some(nonce)=headers.get("x-stealthbridge-nonce").and_then(|v|v.to_str().ok())
  .and_then(|s|Uuid::parse_str(s).ok()).filter(|n|!n.is_nil()) else{
   return StatusCode::UNAUTHORIZED.into_response()
 };
 let digest=hex::encode(Sha256::digest(&body));
 let Some(account)=account_for(&headers,Some(secret),"PATCH",&nonce.to_string(),&digest,now_unix()) else{
  return StatusCode::UNAUTHORIZED.into_response()
 };
 let Ok(change)=serde_json::from_slice::<ProfileChanges>(&body) else{
  return StatusCode::BAD_REQUEST.into_response();
 };
 if !change.valid(){return StatusCode::BAD_REQUEST.into_response();}
 let Some(db)=state.db.as_ref() else{return StatusCode::SERVICE_UNAVAILABLE.into_response();};
 let result=tokio::time::timeout(Duration::from_secs(4),save(db,&account,nonce,&change)).await;
 match result{
  Ok(Ok(Some(profile)))=>([
   (header::CACHE_CONTROL,HeaderValue::from_static("private, no-store"))
  ],Json(envelope(account,Some(profile)))).into_response(),
  Ok(Ok(None))=>StatusCode::CONFLICT.into_response(),
  _=>StatusCode::SERVICE_UNAVAILABLE.into_response()
 }
}
async fn save(
 db:&PgPool,account:&str,nonce:Uuid,change:&ProfileChanges
)->Result<Option<ProfileRow>,sqlx::Error>{
 let mut tx=db.begin().await?;
 // Atomic creation and one-time update receipt. A replay rolls back ALL
 // changes, including the initial insert, when the transaction is dropped.
 sqlx::query("INSERT INTO customer_profiles
  (account_address,display_name,use_case,residence_country)
  VALUES ($1,$2,$3,$4) ON CONFLICT(account_address) DO NOTHING")
  .bind(account).bind(&change.display_name).bind(&change.use_case)
  .bind(&change.residence_country).execute(&mut *tx).await?;
 let claimed=sqlx::query_scalar::<_,Uuid>(
  "INSERT INTO customer_profile_update_receipts(nonce,account_address)
   VALUES ($1,$2) ON CONFLICT(nonce) DO NOTHING RETURNING nonce"
 ).bind(nonce).bind(account).fetch_optional(&mut *tx).await?;
 if claimed.is_none(){return Ok(None);}
 let row=sqlx::query("UPDATE customer_profiles SET
  display_name=$2,use_case=$3,residence_country=$4,updated_at=now()
  WHERE account_address=$1
  RETURNING display_name,use_case,residence_country,
   EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at_unix")
  .bind(account).bind(&change.display_name).bind(&change.use_case)
  .bind(&change.residence_country).fetch_one(&mut *tx).await?;
 let result=row_value(row)?;
 tx.commit().await?;
 Ok(Some(result))
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]
 fn preferences_reject_untrusted_kyc_claims_and_unsigned_contexts(){
  let valid=ProfileChanges{display_name:"StealthBridge User".into(),
   use_case:"personal".into(),residence_country:Some("NG".into())};
  assert!(valid.valid());
  assert!(!ProfileChanges{display_name:" ".into(),..valid.clone()}.valid());
  assert!(!ProfileChanges{display_name:"<script>".into(),..valid.clone()}.valid());
  assert!(!ProfileChanges{use_case:"kyc_approved".into(),..valid.clone()}.valid());
  assert!(!ProfileChanges{residence_country:Some("NGA".into()),..valid.clone()}.valid());
  assert!(serde_json::from_str::<ProfileChanges>(
   r#"{"display_name":"Alice","use_case":"personal","residence_country":null,"kyc_verified":true}"#).is_err());
 }
 #[test]
 fn request_context_cannot_change_method_nonce_or_digest(){
  let secret=b"test-secret-more-than-thirty-two-characters";
  let addr="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
  let now=1_800_000_000_i64;
  let stamp=now.to_string();
  let id=Uuid::new_v4().to_string();
  let digest="b".repeat(64);
  let message=format!("{DOMAIN}\nPATCH\n{PATH}\n{addr}\n{stamp}\n{id}\n{digest}\n");
  let mut mac=Mac256::new_from_slice(secret).unwrap();
  mac.update(message.as_bytes());
  let signature=hex::encode(mac.finalize().into_bytes());
  let mut headers=HeaderMap::new();
  headers.insert("x-stealthbridge-account",HeaderValue::from_str(addr).unwrap());
  headers.insert("x-stealthbridge-issued-at",HeaderValue::from_str(&stamp).unwrap());
  headers.insert("x-stealthbridge-signature",HeaderValue::from_str(&signature).unwrap());
  assert_eq!(account_for(&headers,Some(secret),"PATCH",&id,&digest,now),Some(addr.to_owned()));
  assert!(account_for(&headers,Some(secret),"GET",&id,&digest,now).is_none());
  assert!(account_for(&headers,Some(secret),"PATCH",&id,"bad",now).is_none());
  assert!(account_for(&headers,Some(secret),"PATCH",&Uuid::new_v4().to_string(),&digest,now).is_none());
  assert!(account_for(&headers,Some(secret),"PATCH",&id,&digest,now+32).is_none());
  assert!(account_for(&headers,None,"PATCH",&id,&digest,now).is_none());
 }
}
