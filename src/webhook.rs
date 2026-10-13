//! Verified-notification inbox foundations, NOT a live provider callback API.
//! The tenant/provider/secret are trusted operator configuration, not values
//! supplied by unauthenticated HTTP body fields.
use hmac::{Hmac,Mac};
use sha2::{Sha256,Digest};
use serde::Deserialize;
use sqlx::{PgPool,Row};
use uuid::Uuid;

type HmacSha256=Hmac<Sha256>;
const MAX_BYTES:usize=65_536;
const MAX_SKEW:i64=300;
const DOMAIN:&[u8]=b"stealthbridge-webhook-v1\n";

#[derive(Debug,PartialEq,Eq)]
pub enum VerifyError{InvalidPayload,BadSignature,Expired,WeakKey}
#[derive(Debug,Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope{event_id:String,event_type:String}
#[derive(Clone,Debug)]
pub struct VerifiedEvent{
 pub event_id:String,
 pub event_type:String,
 pub payload_sha256:String,
}
fn id_ok(s:&str)->bool{
 (8..=128).contains(&s.len()) &&
  s.bytes().all(|b|b.is_ascii_alphanumeric() || b":_-".contains(&b))
}
fn type_ok(s:&str)->bool{
 (3..=128).contains(&s.len()) &&
  s.bytes().all(|b|b.is_ascii_alphanumeric() || b":._-".contains(&b))
}
pub fn verify_event(
 raw:&[u8], timestamp:&str, signature_hex:&str,
 secret:&[u8], now_unix:i64,
)->Result<VerifiedEvent,VerifyError>{
 if secret.len()<32{return Err(VerifyError::WeakKey);}
 if raw.is_empty() || raw.len()>MAX_BYTES || timestamp.is_empty() ||
    timestamp.len()>20 || !timestamp.bytes().all(|b|b.is_ascii_digit()) ||
    signature_hex.len()!=64 || !signature_hex.bytes().all(|b|b.is_ascii_hexdigit()){
    return Err(VerifyError::InvalidPayload);
 }
 let timestamp_sec=timestamp.parse::<i64>().map_err(|_|VerifyError::InvalidPayload)?;
 let skew=now_unix.checked_sub(timestamp_sec).ok_or(VerifyError::Expired)?;
 if !(-MAX_SKEW..=MAX_SKEW).contains(&skew){return Err(VerifyError::Expired);}
 let signature=hex::decode(signature_hex).map_err(|_|VerifyError::BadSignature)?;
 let mut mac=HmacSha256::new_from_slice(secret).map_err(|_|VerifyError::WeakKey)?;
 mac.update(DOMAIN);
 mac.update(timestamp.as_bytes());
 mac.update(b"\n");
 mac.update(raw);
 mac.verify_slice(&signature).map_err(|_|VerifyError::BadSignature)?;
 // Payload deserialization occurs only after authentication.
 let data:Envelope=serde_json::from_slice(raw).map_err(|_|VerifyError::InvalidPayload)?;
 if !id_ok(&data.event_id)||!type_ok(&data.event_type){
    return Err(VerifyError::InvalidPayload);
 }
 Ok(VerifiedEvent{
    event_id:data.event_id,
    event_type:data.event_type,
    payload_sha256:format!("{:x}",Sha256::digest(raw)),
 })
}
#[derive(Debug)]
pub enum InboxError{Collision,InvalidIdentifier,Database(sqlx::Error)}
impl From<sqlx::Error> for InboxError{
 fn from(e:sqlx::Error)->Self{Self::Database(e)}
}
#[derive(Debug,PartialEq,Eq)]
pub enum InboxResult{Inserted,Duplicate}

/// Store only authenticated, tenant-scoped metadata and content digest.
/// Does not emit transactions, execute payouts or mutate settlement status.
pub async fn record_event(
 pool:&PgPool,tenant:Uuid,provider:&str,event:&VerifiedEvent,
)->Result<InboxResult,InboxError>{
 if !id_ok(provider)||!id_ok(&event.event_id)||!type_ok(&event.event_type)||
    event.payload_sha256.len()!=64 ||
    !event.payload_sha256.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
    return Err(InboxError::InvalidIdentifier);
 }
 let mut tx=pool.begin().await?;
 let created=sqlx::query(
  "INSERT INTO provider_event_inbox(organization_id,provider,event_id,event_type,payload_sha256) \
   VALUES ($1,$2,$3,$4,$5) \
   ON CONFLICT(organization_id,provider,event_id) DO NOTHING RETURNING event_id"
 ).bind(tenant).bind(provider).bind(&event.event_id).bind(&event.event_type)
  .bind(&event.payload_sha256).fetch_optional(&mut *tx).await?;
 if created.is_some(){
    tx.commit().await?;
    return Ok(InboxResult::Inserted);
 }
 let prior=sqlx::query(
  "SELECT payload_sha256,event_type FROM provider_event_inbox \
   WHERE organization_id=$1 AND provider=$2 AND event_id=$3 FOR UPDATE"
 ).bind(tenant).bind(provider).bind(&event.event_id).fetch_one(&mut *tx).await?;
 let digest:String=prior.try_get("payload_sha256")?;
 let kind:String=prior.try_get("event_type")?;
 if digest!=event.payload_sha256||kind!=event.event_type{return Err(InboxError::Collision);}
 tx.commit().await?;
 Ok(InboxResult::Duplicate)
}

/// A reviewed key entry is supplied by trusted operator configuration.
/// Keys are never fetched from untrusted payload fields or stored in the inbox.
#[derive(Clone,Copy)]
pub struct ProviderKey<'a>{
 pub id:&'a str,
 pub secret:&'a [u8],
 pub valid_from_unix:i64,
 pub valid_until_unix:i64,
}
#[derive(Debug)]
pub struct ScopedVerifiedEvent{
 pub tenant:Uuid,
 pub provider:String,
 pub key_id:String,
 pub event:VerifiedEvent,
}
const SCOPED_DOMAIN:&[u8]=b"stealthbridge-provider-callback-v2\n";
const MAX_KEYRING:usize=8;

/// Verify the authenticated tenant/provider/key identity against the exact
/// raw message bytes. Caller MUST select tenant/provider from trusted router
/// configuration; NEVER from an unsigned request body or arbitrary header.
pub fn verify_scoped_event(
 raw:&[u8],timestamp:&str,signature_hex:&str,
 tenant:Uuid,provider:&str,key_id:&str,keyring:&[ProviderKey<'_>],
 now_unix:i64,
)->Result<ScopedVerifiedEvent,VerifyError>{
 if tenant.is_nil()||!id_ok(provider)||!id_ok(key_id)||
    keyring.is_empty()||keyring.len()>MAX_KEYRING||
    keyring.iter().any(|k| !id_ok(k.id)||k.secret.len()<32||
        k.valid_from_unix>=k.valid_until_unix)||
    keyring.iter().enumerate().any(|(i,k)|keyring[..i].iter().any(|prior|prior.id==k.id)){
    return Err(VerifyError::InvalidPayload);
 }
 if raw.is_empty()||raw.len()>MAX_BYTES||timestamp.is_empty()||timestamp.len()>20||
    !timestamp.bytes().all(|b|b.is_ascii_digit())||
    signature_hex.len()!=64||!signature_hex.bytes().all(|b|b.is_ascii_hexdigit()){
    return Err(VerifyError::InvalidPayload);
 }
 let sent_at=timestamp.parse::<i64>().map_err(|_|VerifyError::InvalidPayload)?;
 let skew=now_unix.checked_sub(sent_at).ok_or(VerifyError::Expired)?;
 if !(-MAX_SKEW..=MAX_SKEW).contains(&skew){return Err(VerifyError::Expired);}
 let key=keyring.iter().find(|entry|entry.id==key_id).ok_or(VerifyError::BadSignature)?;
 if sent_at<key.valid_from_unix||sent_at>key.valid_until_unix||
    now_unix>key.valid_until_unix{return Err(VerifyError::Expired);}
 let signature=hex::decode(signature_hex).map_err(|_|VerifyError::BadSignature)?;
 let mut mac=HmacSha256::new_from_slice(key.secret).map_err(|_|VerifyError::WeakKey)?;
 mac.update(SCOPED_DOMAIN);
 mac.update(tenant.as_bytes());mac.update(b"\n");
 mac.update(provider.as_bytes());mac.update(b"\n");
 mac.update(key_id.as_bytes());mac.update(b"\n");
 mac.update(timestamp.as_bytes());mac.update(b"\n");
 mac.update(raw);
 mac.verify_slice(&signature).map_err(|_|VerifyError::BadSignature)?;
 // Parsing is *after* scope-aware authentication. Ignore any untrusted
 // tenant/provider claims: the envelope deliberately has no such fields.
 let data:Envelope=serde_json::from_slice(raw).map_err(|_|VerifyError::InvalidPayload)?;
 if !id_ok(&data.event_id)||!type_ok(&data.event_type){
    return Err(VerifyError::InvalidPayload);
 }
 Ok(ScopedVerifiedEvent{
    tenant,provider:provider.to_owned(),key_id:key_id.to_owned(),
    event:VerifiedEvent{
      event_id:data.event_id,event_type:data.event_type,
      payload_sha256:format!("{:x}",Sha256::digest(raw)),
    },
 })
}
/// Insert only the verified tenant/provider tuple. No settlement mutation,
/// payout dispatch, event processing or provider callback route is enabled.
pub async fn record_scoped_event(
 pool:&PgPool,verified:&ScopedVerifiedEvent,
)->Result<InboxResult,InboxError>{
 record_event(pool,verified.tenant,&verified.provider,&verified.event).await
}

#[cfg(test)]
mod tests{
 use super::*;
 #[test]
 fn scoped_hmac_prevents_wrong_tenant_provider_rotation_and_replay_context(){
    let tenant=Uuid::parse_str("e1a4d2c0-f715-4011-9cef-391a1fdd54fb").unwrap();
    let other=Uuid::parse_str("e1a4d2c0-f715-4011-9cef-391a1fdd54fc").unwrap();
    let provider="fixture-provider";
    let id="rotation-key-01";
    let key=b"review-only-test-secret-not-for-real-provider-use";
    let alternate=b"different-review-only-test-secret-for-rotation";
    let issued="1760000100";
    let raw=br#"{"event_id":"fixture-event-002","event_type":"payout.pending"}"#;
    let keys=[
       ProviderKey{id,secret:key,valid_from_unix:1_760_000_000,valid_until_unix:1_760_010_000},
       ProviderKey{id:"rotation-key-02",secret:alternate,valid_from_unix:1_760_000_050,valid_until_unix:1_760_020_000},
    ];
    let mut mac=HmacSha256::new_from_slice(key).unwrap();
    mac.update(SCOPED_DOMAIN);
    mac.update(tenant.as_bytes());mac.update(b"\n");
    mac.update(provider.as_bytes());mac.update(b"\n");
    mac.update(id.as_bytes());mac.update(b"\n");
    mac.update(issued.as_bytes());mac.update(b"\n");mac.update(raw);
    let signature=hex::encode(mac.finalize().into_bytes());
    let verify=|tenant,provider,id,keys:&[ProviderKey<'_>],now|{
      verify_scoped_event(raw,issued,&signature,tenant,provider,id,keys,now)
    };
    let event=verify(tenant,provider,id,&keys,1_760_000_150).unwrap();
    assert_eq!(event.tenant,tenant);
    assert_eq!(event.provider,provider);
    assert_eq!(event.key_id,id);
    assert_eq!(event.event.event_type,"payout.pending");
    assert!(matches!(verify(other,provider,id,&keys,1_760_000_150),Err(VerifyError::BadSignature)));
    assert!(matches!(verify(tenant,"other-provider",id,&keys,1_760_000_150),Err(VerifyError::BadSignature)));
    assert!(matches!(verify(tenant,provider,"rotation-key-02",&keys,1_760_000_150),Err(VerifyError::BadSignature)));
    assert!(matches!(verify(tenant,provider,id,&keys,1_760_010_001),Err(VerifyError::Expired)));
    assert!(matches!(verify_scoped_event(b"tampered",issued,&signature,tenant,provider,id,&keys,1_760_000_150),Err(VerifyError::BadSignature)));
    let duplicate=[keys[0],keys[0]];
    assert!(matches!(verify(tenant,provider,id,&duplicate,1_760_000_150),Err(VerifyError::InvalidPayload)));
    assert!(matches!(verify(Uuid::nil(),provider,id,&keys,1_760_000_150),Err(VerifyError::InvalidPayload)));
    // Out-of-order verified notifications are isolated inbox metadata: they
    // do not call settlement::transition or trigger a payout.
    let earlier=br#"{"event_id":"fixture-event-003","event_type":"payout.completed"}"#;
    assert!(verify_scoped_event(earlier,issued,&signature,tenant,provider,id,&keys,1_760_000_150).is_err());
 }
 #[test]
 fn signature_tampering_and_expired_delivery_rejected(){
    let key=b"unit-test-only-configured-secret-must-not-be-reused";
    let body=br#"{"event_id":"fixture-event-001","event_type":"fixture.notice"}"#;
    let timestamp="1760000000";
    let mut mac=HmacSha256::new_from_slice(key).unwrap();
    mac.update(DOMAIN);mac.update(timestamp.as_bytes());mac.update(b"\n");mac.update(body);
    let signature=hex::encode(mac.finalize().into_bytes());
    let result=verify_event(body,timestamp,&signature,key,1_760_000_100).unwrap();
    assert_eq!(result.event_id,"fixture-event-001");
    assert_eq!(result.event_type,"fixture.notice");
    assert_eq!(result.payload_sha256.len(),64);
    assert!(matches!(verify_event(body,timestamp,&signature,key,1_760_000_400),Err(VerifyError::Expired)));
    assert!(matches!(verify_event(b"malicious",timestamp,&signature,key,1_760_000_100),Err(VerifyError::BadSignature)));
    assert!(matches!(verify_event(body,timestamp,&"0".repeat(64),key,1_760_000_100),Err(VerifyError::BadSignature)));
    assert!(matches!(verify_event(body,timestamp,&signature,b"short",1_760_000_100),Err(VerifyError::WeakKey)));
 }
}
