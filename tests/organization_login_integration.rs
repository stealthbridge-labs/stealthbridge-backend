//! CI PostgreSQL-backed wallet ownership, one-use nonce and membership tests.
//! Fixtures use synthetic Ed25519 keys; no real Stellar account or funds.
use ed25519_dalek::{Signer,SigningKey};
use sqlx::PgPool;
use stealthbridge_backend::{
    authz::Permission,
    org_auth::{issue_login_challenge,issue_read_session,require_read_session,
               verify_login_challenge,AuthError,VerifyLogin},
};
use uuid::Uuid;

fn public_strkey(public:[u8;32])->String{
 let mut payload=[0_u8;35];
 payload[0]=6<<3;
 payload[1..33].copy_from_slice(&public);
 let mut crc=0_u16;
 for byte in &payload[..33]{
  crc^=u16::from(*byte)<<8;
  for _ in 0..8{
   crc=if crc&0x8000!=0{(crc<<1)^0x1021}else{crc<<1};
  }
 }
 payload[33..].copy_from_slice(&crc.to_le_bytes());
 let alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
 let mut value=0_u32;
 let mut bits=0_u32;
 let mut result=String::new();
 for byte in payload{
  value=(value<<8)|u32::from(byte);
  bits+=8;
  while bits>=5{
    bits-=5;
    result.push(alphabet[((value>>bits)&31) as usize] as char);
    value&=(1<<bits)-1;
  }
 }
 assert_eq!(result.len(),56);
 result
}
#[tokio::test]
async fn organization_auth_is_one_use_signed_and_rechecks_revocation(){
 let uri=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
 let pool=PgPool::connect(&uri).await.expect("connection");
 sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
 let signing=SigningKey::from_bytes(&[7_u8;32]);
 let account=public_strkey(signing.verifying_key().to_bytes());
 let alpha=Uuid::new_v4();
 let beta=Uuid::new_v4();
 let domain="app.stealthbridge.example";
 let now=1_760_000_100;
 let secret=b"unit-tests-only-organization-session-key-must-be-rotated";
 for org in [alpha,beta]{
    sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES($1,'TEST_ORG_AUTH','active')")
       .bind(org).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,'viewer')")
       .bind(org).bind(&account).execute(&pool).await.unwrap();
 }
 let issued=issue_login_challenge(&pool,alpha,&account,domain,now).await.unwrap();
 assert!(issued.message.contains("Test SDF Network ; September 2015"));
 assert!(issued.message.contains(&alpha.to_string()));
 assert_eq!(issued.expires_at_unix-now,300);
 let signed=signing.sign(issued.message.as_bytes());
 let signed_hex=hex::encode(signed.to_bytes());
 let input=|organization,domain,signature_hex|VerifyLogin{
  id:issued.id,organization,account:&account,domain,
  nonce:&issued.nonce,signature_hex,now_unix:now+5
 };
 let altered=hex::encode(signing.sign(b"wrong-message").to_bytes());
 assert!(matches!(verify_login_challenge(&pool,input(alpha,domain,&altered)).await,
  Err(AuthError::InvalidSignature)));
 assert!(matches!(verify_login_challenge(&pool,input(beta,domain,&signed_hex)).await,
  Err(AuthError::Unauthorized)));
 assert!(matches!(verify_login_challenge(&pool,input(alpha,"different.example",&signed_hex)).await,
  Err(AuthError::Unauthorized)));
 let identity=verify_login_challenge(&pool,input(alpha,domain,&signed_hex)).await.unwrap();
 assert_eq!(identity.account,account);
 assert!(matches!(verify_login_challenge(&pool,input(alpha,domain,&signed_hex)).await,
  Err(AuthError::Replay)));
 let session=issue_read_session(&identity,secret).unwrap();
 assert!(require_read_session(&pool,&format!("Bearer {session}"),secret,domain,
  alpha,Permission::ReadAudit,now+10).await.is_ok());
 assert!(matches!(require_read_session(&pool,&format!("Bearer {session}"),secret,domain,
  beta,Permission::ReadAudit,now+10).await,Err(AuthError::Unauthorized)));
 assert!(matches!(require_read_session(&pool,&format!("Bearer {session}"),secret,domain,
  alpha,Permission::ManageMembers,now+10).await,Err(AuthError::Unauthorized)));
 let expired=issue_login_challenge(&pool,alpha,&account,domain,now).await.unwrap();
 let expired_sig=hex::encode(signing.sign(expired.message.as_bytes()).to_bytes());
 let late=VerifyLogin{id:expired.id,organization:alpha,account:&account,
    domain,nonce:&expired.nonce,signature_hex:&expired_sig,now_unix:now+301};
 assert!(matches!(verify_login_challenge(&pool,late).await,Err(AuthError::Expired)));
 sqlx::query("UPDATE organization_members SET revoked_at=now() WHERE organization_id=$1")
  .bind(alpha).execute(&pool).await.unwrap();
 assert!(matches!(require_read_session(&pool,&format!("Bearer {session}"),secret,domain,
  alpha,Permission::ReadAudit,now+10).await,Err(AuthError::Unauthorized)));
 assert!(matches!(issue_login_challenge(&pool,alpha,&account,domain,now).await,
  Err(AuthError::Unauthorized)));
 for org in [alpha,beta]{
  sqlx::query("DELETE FROM organization_login_challenges WHERE organization_id=$1")
    .bind(org).execute(&pool).await.unwrap();
  sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
    .bind(org).execute(&pool).await.unwrap();
  sqlx::query("DELETE FROM organizations WHERE id=$1")
    .bind(org).execute(&pool).await.unwrap();
 }
}
