//! Off-route, Testnet-only Stellar account authentication foundation.
//! A *verified* Ed25519 signature is required; a checksum-valid G address alone
//! never establishes identity. No login/settlement HTTP endpoints are enabled.
use crate::{authz::{self,Permission,Role},wallet};
use ed25519_dalek::{Signature,VerifyingKey};
use hmac::{Hmac,Mac};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use sqlx::{PgPool,Row};
use uuid::Uuid;

type SessionHmac=Hmac<Sha256>;
const TESTNET:&str="Test SDF Network ; September 2015";
const CHALLENGE_DOMAIN:&[u8]=b"StealthBridge organizational login v1\n";
const SESSION_DOMAIN:&[u8]=b"StealthBridge scoped read session v1\n";
const CHALLENGE_SECONDS:i64=300;
const SESSION_SECONDS:i64=900;
const MAX_SESSION_BYTES:usize=2048;

#[derive(Debug)]
pub enum AuthError{
 InvalidRequest,InvalidSignature,Expired,Replay,Unauthorized,Database(sqlx::Error),
}
impl From<sqlx::Error> for AuthError{
 fn from(error:sqlx::Error)->Self{Self::Database(error)}
}
fn valid_domain(domain:&str)->bool{
 domain.len()>=4&&domain.len()<=253&&
 domain.bytes().all(|x|x.is_ascii_lowercase()||x.is_ascii_digit()||x==b'.'||x==b'-')&&
 domain.contains('.')&&!domain.starts_with('.')&&!domain.ends_with('.')&&
 !domain.contains("..")
}
fn valid_subject(subject:&str)->bool{wallet::decode_account_address(subject).is_some()}
fn nonce_digest(nonce:&str)->String{
 format!("{:x}",Sha256::digest(nonce.as_bytes()))
}
fn signed_message(
 domain:&str,organization:Uuid,account:&str,nonce:&str,issued:i64,expires:i64,
)->String{
 format!("{}domain:{}\nnetwork:{}\norganization:{}\naccount:{}\nnonce:{}\nissued:{}\nexpires:{}\n",
  core::str::from_utf8(CHALLENGE_DOMAIN).expect("constant ASCII"),
  domain,TESTNET,organization,account,nonce,issued,expires)
}

pub struct LoginChallenge{
 pub id:Uuid,
 pub organization:Uuid,
 pub account:String,
 pub domain:String,
 pub nonce:String,
 pub message:String,
 pub issued_at_unix:i64,
 pub expires_at_unix:i64,
}
pub struct VerifyLogin<'a>{
 pub id:Uuid,
 pub organization:Uuid,
 pub account:&'a str,
 pub domain:&'a str,
 pub nonce:&'a str,
 pub signature_hex:&'a str,
 pub now_unix:i64,
}

/// Only a caller-controlled *initiation*; the caller's asserted account is
/// checked against an ACTIVE tenant membership before any nonce is issued.
/// An immutable signed network/domain/organization context prevents phishing
/// reuse and cross-tenant login. No wallet seed or proof witness is stored.
pub async fn issue_login_challenge(
 pool:&PgPool,organization:Uuid,account:&str,domain:&str,now_unix:i64,
)->Result<LoginChallenge,AuthError>{
 if organization.is_nil()||!valid_domain(domain)||!valid_subject(account)||now_unix<=0 {
   return Err(AuthError::InvalidRequest);
 }
 authz::authorize_member(pool,organization,account,Permission::ReadAudit).await
   .map_err(|_|AuthError::Unauthorized)?;
 let expires=now_unix.checked_add(CHALLENGE_SECONDS).ok_or(AuthError::InvalidRequest)?;
 let nonce=format!("{}{}",Uuid::new_v4().simple(),Uuid::new_v4().simple());
 let id=Uuid::new_v4();
 let message=signed_message(domain,organization,account,&nonce,now_unix,expires);
 sqlx::query("INSERT INTO organization_login_challenges \
  (id,organization_id,subject,domain,nonce_sha256,issued_at_unix,expires_at_unix) \
  VALUES ($1,$2,$3,$4,$5,$6,$7)")
  .bind(id).bind(organization).bind(account).bind(domain).bind(nonce_digest(&nonce))
  .bind(now_unix).bind(expires).execute(pool).await?;
 Ok(LoginChallenge{
  id,organization,account:account.to_owned(),domain:domain.to_owned(),
  nonce,message,issued_at_unix:now_unix,expires_at_unix:expires,
 })
}

#[derive(Debug,Clone)]
pub struct VerifiedIdentity{
 pub organization:Uuid,
 pub account:String,
 pub domain:String,
 pub authenticated_at_unix:i64,
}

/// Atomic consuming UPDATE after signature verification prevents concurrent
/// replay. A wrong signature does not consume the legitimate wallet's nonce.
pub async fn verify_login_challenge(
 pool:&PgPool,input:VerifyLogin<'_>,
)->Result<VerifiedIdentity,AuthError>{
 if input.id.is_nil()||input.organization.is_nil()||
    !valid_domain(input.domain)||!valid_subject(input.account)||
    input.nonce.len()!=64||!input.nonce.bytes().all(|b|b.is_ascii_hexdigit())||
    input.signature_hex.len()!=128||
    !input.signature_hex.bytes().all(|b|b.is_ascii_hexdigit()) {
     return Err(AuthError::InvalidRequest);
 }
 let record=sqlx::query("SELECT nonce_sha256,issued_at_unix,expires_at_unix,consumed_at_unix \
    FROM organization_login_challenges \
    WHERE id=$1 AND organization_id=$2 AND subject=$3 AND domain=$4")
   .bind(input.id).bind(input.organization).bind(input.account).bind(input.domain)
   .fetch_optional(pool).await?.ok_or(AuthError::Unauthorized)?;
 let stored:String=record.try_get("nonce_sha256")?;
 let issued:i64=record.try_get("issued_at_unix")?;
 let expires:i64=record.try_get("expires_at_unix")?;
 let consumed:Option<i64>=record.try_get("consumed_at_unix")?;
 if consumed.is_some(){return Err(AuthError::Replay);}
 if input.now_unix<issued||input.now_unix>expires||expires-issued!=CHALLENGE_SECONDS {
     return Err(AuthError::Expired);
 }
 if stored!=nonce_digest(input.nonce){return Err(AuthError::Unauthorized);}
 let key=wallet::decode_account_address(input.account).ok_or(AuthError::InvalidRequest)?;
 let verifier=VerifyingKey::from_bytes(&key).map_err(|_|AuthError::InvalidSignature)?;
 let bytes=hex::decode(input.signature_hex).map_err(|_|AuthError::InvalidSignature)?;
 let signature=Signature::from_slice(&bytes).map_err(|_|AuthError::InvalidSignature)?;
 let message=signed_message(input.domain,input.organization,input.account,input.nonce,issued,expires);
 verifier.verify_strict(message.as_bytes(),&signature)
   .map_err(|_|AuthError::InvalidSignature)?;
 // Check the member again BEFORE issuing a session; revocation closes access
 // even when a challenge was created while membership was active.
 authz::authorize_member(pool,input.organization,input.account,Permission::ReadAudit).await
   .map_err(|_|AuthError::Unauthorized)?;
 let taken=sqlx::query_scalar::<_,Uuid>("UPDATE organization_login_challenges \
   SET consumed_at_unix=$1 WHERE id=$2 AND organization_id=$3 \
   AND consumed_at_unix IS NULL AND expires_at_unix>=$1 RETURNING id")
  .bind(input.now_unix).bind(input.id).bind(input.organization)
  .fetch_optional(pool).await?;
 if taken.is_none(){return Err(AuthError::Replay);}
 Ok(VerifiedIdentity{
  organization:input.organization,account:input.account.to_owned(),
  domain:input.domain.to_owned(),authenticated_at_unix:input.now_unix,
 })
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionClaims{
 purpose:String,organization:Uuid,account:String,domain:String,
 network:String,issued_at_unix:i64,expires_at_unix:i64,
}
pub fn issue_read_session(identity:&VerifiedIdentity,secret:&[u8])->Result<String,AuthError>{
 if secret.len()<32||identity.organization.is_nil()||
    !valid_subject(&identity.account)||!valid_domain(&identity.domain){
     return Err(AuthError::InvalidRequest);
 }
 let expiry=identity.authenticated_at_unix.checked_add(SESSION_SECONDS)
   .ok_or(AuthError::InvalidRequest)?;
 let claims=SessionClaims{
  purpose:"organization_read_only".into(),organization:identity.organization,
  account:identity.account.clone(),domain:identity.domain.clone(),
  network:TESTNET.into(),issued_at_unix:identity.authenticated_at_unix,expires_at_unix:expiry,
 };
 let message=serde_json::to_vec(&claims).map_err(|_|AuthError::InvalidRequest)?;
 let mut mac=SessionHmac::new_from_slice(secret).map_err(|_|AuthError::InvalidRequest)?;
 mac.update(SESSION_DOMAIN);mac.update(&message);
 Ok(format!("v1.{}.{}",hex::encode(message),hex::encode(mac.finalize().into_bytes())))
}
fn verify_session_claims(token:&str,secret:&[u8],domain:&str,now:i64)
 ->Result<SessionClaims,AuthError>{
 if secret.len()<32||!valid_domain(domain)||token.len()>MAX_SESSION_BYTES {
    return Err(AuthError::Unauthorized);
 }
 let mut parts=token.split('.');
 if parts.next()!=Some("v1"){return Err(AuthError::Unauthorized);}
 let message=hex::decode(parts.next().ok_or(AuthError::Unauthorized)?)
   .map_err(|_|AuthError::Unauthorized)?;
 let signature=hex::decode(parts.next().ok_or(AuthError::Unauthorized)?)
   .map_err(|_|AuthError::Unauthorized)?;
 if parts.next().is_some()||message.len()>768||signature.len()!=32{
    return Err(AuthError::Unauthorized);
 }
 let mut mac=SessionHmac::new_from_slice(secret).map_err(|_|AuthError::Unauthorized)?;
 mac.update(SESSION_DOMAIN);mac.update(&message);
 mac.verify_slice(&signature).map_err(|_|AuthError::Unauthorized)?;
 let claims:SessionClaims=serde_json::from_slice(&message).map_err(|_|AuthError::Unauthorized)?;
 if claims.purpose!="organization_read_only"||claims.network!=TESTNET||
    claims.domain!=domain||claims.organization.is_nil()||
    !valid_subject(&claims.account)||claims.issued_at_unix>now||
    claims.expires_at_unix<=now||
    claims.expires_at_unix.checked_sub(claims.issued_at_unix)!=Some(SESSION_SECONDS) {
    return Err(AuthError::Unauthorized);
 }
 Ok(claims)
}

/// Resolve an authenticated session to a tenant-bound identity. A trusted
/// configured domain and secret are required; no submitted request field may
/// override either. Active membership is rechecked on every invocation.
pub async fn require_read_identity(
 pool:&PgPool,bearer:&str,secret:&[u8],trusted_domain:&str,
 organization:Uuid,permission:Permission,now_unix:i64,
)->Result<VerifiedIdentity,AuthError>{
 let token=bearer.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
 let claims=verify_session_claims(token,secret,trusted_domain,now_unix)?;
 if claims.organization!=organization{return Err(AuthError::Unauthorized);}
 authz::authorize_member(pool,organization,&claims.account,permission).await
   .map_err(|_|AuthError::Unauthorized)?;
 Ok(VerifiedIdentity{
  organization:claims.organization,account:claims.account,domain:claims.domain,
  authenticated_at_unix:claims.issued_at_unix,
 })
}

/// Middleware-ready tenant-scoped guard for *future read-only* routes. The
/// server MUST supply the expected tenant from a trusted route and the
/// domain/secret from trusted config, not from user-submitted headers.
/// No actual authenticated tenant HTTP routes are enabled in this milestone.
pub async fn require_read_session(
 pool:&PgPool,bearer:&str,secret:&[u8],trusted_domain:&str,
 organization:Uuid,permission:Permission,now_unix:i64,
)->Result<Role,AuthError>{
 let token=bearer.strip_prefix("Bearer ").ok_or(AuthError::Unauthorized)?;
 let claims=verify_session_claims(token,secret,trusted_domain,now_unix)?;
 if claims.organization!=organization{return Err(AuthError::Unauthorized);}
 authz::authorize_member(pool,organization,&claims.account,permission).await
   .map_err(|_|AuthError::Unauthorized)
}

#[cfg(test)]
mod tests{
 use super::*;
 use ed25519_dalek::{Signer,SigningKey};
 const KEY:[u8;32]=[7;32];
 fn local_identity()->VerifiedIdentity{
   VerifiedIdentity{organization:Uuid::new_v4(),
      account:"GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX".into(),
      domain:"staging.stealthbridge.example".into(),authenticated_at_unix:1_760_000_000}
 }
 #[test]
 fn sessions_bind_domain_chain_expiration_and_organization(){
  let identity=local_identity();
  let secret=b"nonproduction-ci-test-only-session-secret-1";
  let token=issue_read_session(&identity,secret).unwrap();
  let actual=verify_session_claims(&token,secret,&identity.domain,identity.authenticated_at_unix+1).unwrap();
  assert_eq!(actual.organization,identity.organization);
  assert_eq!(actual.account,identity.account);
  assert!(verify_session_claims(&token,secret,"evil.example.com",identity.authenticated_at_unix+1).is_err());
  assert!(verify_session_claims(&token,secret,&identity.domain,identity.authenticated_at_unix+SESSION_SECONDS).is_err());
  assert!(verify_session_claims(&token,b"different-test-session-secret-should-fail",&identity.domain,identity.authenticated_at_unix+1).is_err());
  // A deterministic mutation must always differ: the original MAC hex
  // may already end with '0' for roughly 1/16 of valid signed sessions.
  let replacement=if token.ends_with('0'){"1"}else{"0"};
  let tampered=format!("{}{}",&token[..token.len()-1],replacement);
  assert!(verify_session_claims(&tampered,secret,&identity.domain,identity.authenticated_at_unix+1).is_err());
  assert!(issue_read_session(&identity,b"short").is_err());
 }
 #[test]
 fn signed_login_cannot_cross_tenant_or_domain(){
   let key=SigningKey::from_bytes(&KEY);
   let org=Uuid::new_v4();
   let nonce="e".repeat(64);
   let msg=signed_message("staging.stealthbridge.example",org,"GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX",
     &nonce,1_760_000_000,1_760_000_300);
   let sig=key.sign(msg.as_bytes());
   assert!(key.verifying_key().verify_strict(msg.as_bytes(),&sig).is_ok());
   let altered=signed_message("another.example.com",org,"GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX",
     &nonce,1_760_000_000,1_760_000_300);
   assert!(key.verifying_key().verify_strict(altered.as_bytes(),&sig).is_err());
   let other=signed_message("staging.stealthbridge.example",Uuid::new_v4(),
      "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX",
      &nonce,1_760_000_000,1_760_000_300);
   assert!(key.verifying_key().verify_strict(other.as_bytes(),&sig).is_err());
 }
 #[test]
 fn login_domains_are_strictly_configured(){
   for domain in ["https://test.example.com","LOCALHOST","unknown","evil.example.com/path","bad..example.com",""]{
    assert!(!valid_domain(domain));
   }
   assert!(valid_domain("staging.stealthbridge.example"));
 }
}