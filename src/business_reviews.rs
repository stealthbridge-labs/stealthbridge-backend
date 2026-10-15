//! Persistent, off-route business review ledger. No funds or smart-contract writes.
//! Only trusted code holding an identity established by org_auth signature/session
//! verification may call these functions. Public HTTP routes are deliberately absent.

use crate::{
    authz::{permits, Permission, Role},
    org_auth::VerifiedIdentity,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug)]
pub enum ReviewStoreError {
    Database(sqlx::Error),
    InvalidInput,
    Unauthorized,
    Conflict,
    NotFound,
    Expired,
    AlreadyReviewed,
    ReviewLimit,
}
impl From<sqlx::Error> for ReviewStoreError {
    fn from(value: sqlx::Error) -> Self { Self::Database(value) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewRegistration {
    pub id: Uuid,
    pub created: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewReceipt {
    pub count: i64,
    pub remaining: i64,
    pub review_count_met: bool,
    /// No database review count can grant payment submission authority.
    pub financial_execution_authorized: bool,
}

fn valid_subject(s: &str) -> bool {
    (8..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}
async fn locked_membership(
    tx: &mut Transaction<'_, Postgres>,
    identity: &VerifiedIdentity,
    permission: Permission,
) -> Result<Role, ReviewStoreError> {
    if identity.organization.is_nil() || !valid_subject(&identity.account) {
        return Err(ReviewStoreError::Unauthorized);
    }
    let role_name: Option<String> = sqlx::query_scalar(
        "SELECT m.role FROM organization_members m JOIN organizations o \
         ON o.id=m.organization_id WHERE m.organization_id=$1 AND m.subject=$2 \
         AND m.revoked_at IS NULL AND o.status='active' FOR UPDATE OF m,o"
    )
    .bind(identity.organization).bind(&identity.account)
    .fetch_optional(&mut **tx).await?;
    let role=role_name.as_deref().and_then(Role::from_db)
        .ok_or(ReviewStoreError::Unauthorized)?;
    if !permits(role,permission) { return Err(ReviewStoreError::Unauthorized); }
    Ok(role)
}

/// Atomic draft registration with tenant-local idempotency. This does not
/// create a settlement intent or authorize spending. The digest is supplied
/// by a trusted canonical request builder, NEVER by unvalidated browser state.
pub async fn create_request(
    pool: &PgPool,
    identity: &VerifiedIdentity,
    key: &str,
    intent_sha256: [u8;32],
    required_reviewers: u8,
    now_unix: i64,
    ttl_seconds: i64,
) -> Result<ReviewRegistration, ReviewStoreError> {
    if !valid_subject(&identity.account)
        || key.len()<16 || key.len()>128
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'_' || b==b'-')
        || intent_sha256==[0u8;32] || !(2..=4).contains(&required_reviewers)
        || now_unix<=0 || !(300..=86_400).contains(&ttl_seconds)
    { return Err(ReviewStoreError::InvalidInput); }
    let expires=now_unix.checked_add(ttl_seconds)
        .ok_or(ReviewStoreError::InvalidInput)?;
    let mut tx=pool.begin().await?;
    locked_membership(&mut tx,identity,Permission::CreateDraft).await?;
    let id=Uuid::new_v4();
    let digest=hex::encode(intent_sha256);
    let inserted:Option<Uuid>=sqlx::query_scalar(
        "INSERT INTO business_review_requests \
         (id,organization_id,initiator,request_key,intent_sha256,required_reviewers,issued_at_unix,expires_at_unix) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (organization_id,request_key) \
         DO NOTHING RETURNING id"
    )
    .bind(id).bind(identity.organization).bind(&identity.account)
    .bind(key).bind(&digest).bind(i16::from(required_reviewers))
    .bind(now_unix).bind(expires).fetch_optional(&mut *tx).await?;
    if let Some(created_id)=inserted {
        tx.commit().await?;
        return Ok(ReviewRegistration{id:created_id,created:true});
    }
    let existing=sqlx::query(
        "SELECT id,initiator,intent_sha256,required_reviewers FROM business_review_requests \
         WHERE organization_id=$1 AND request_key=$2 FOR UPDATE"
    ).bind(identity.organization).bind(key).fetch_optional(&mut *tx).await?
        .ok_or(ReviewStoreError::NotFound)?;
    let previous_initiator:String=existing.try_get("initiator")?;
    let previous_digest:String=existing.try_get("intent_sha256")?;
    let previous_required:i16=existing.try_get("required_reviewers")?;
    if previous_initiator!=identity.account || previous_digest!=digest
        || previous_required!=i16::from(required_reviewers) {
        return Err(ReviewStoreError::Conflict);
    }
    let prior_id:Uuid=existing.try_get("id")?;
    tx.commit().await?;
    Ok(ReviewRegistration{id:prior_id,created:false})
}

/// Preferred entry point for trusted draft orchestration: compute the exact
/// network/tenant/actor/action digest before storing it. The returned hash
/// enables subsequent review lookups but carries no financial authority.
pub async fn create_canonical_request(
    pool: &PgPool,
    identity: &VerifiedIdentity,
    operation: crate::business_envelope::BusinessOperation,
    reference: &str,
    key: &str,
    required_reviewers: u8,
    now_unix: i64,
    ttl_seconds: i64,
) -> Result<(ReviewRegistration, [u8;32]), ReviewStoreError> {
    let digest=crate::business_envelope::digest_business_envelope(
        identity.organization,&identity.account,operation,reference,key
    ).map_err(|_| ReviewStoreError::InvalidInput)?;
    let registration=create_request(
        pool,identity,key,digest,required_reviewers,now_unix,ttl_seconds
    ).await?;
    Ok((registration,digest))
}

/// This writes only a review observation after rechecking active tenant role
/// under a row lock. Reviewer's trusted identity must originate from verified
/// login/session middleware; never accept an arbitrary submitted reviewer name.
pub async fn record_review(
    pool: &PgPool,
    identity: &VerifiedIdentity,
    request_id: Uuid,
    expected_sha256: [u8;32],
    now_unix: i64,
) -> Result<ReviewReceipt, ReviewStoreError> {
    if request_id.is_nil() || expected_sha256==[0u8;32] || now_unix<=0 {
        return Err(ReviewStoreError::InvalidInput);
    }
    let mut tx=pool.begin().await?;
    locked_membership(&mut tx,identity,Permission::ApproveIntent).await?;
    // Lock the request to serialize competing reviewers and enforce the cap.
    let row=sqlx::query(
        "SELECT initiator,intent_sha256,required_reviewers,issued_at_unix,expires_at_unix \
         FROM business_review_requests WHERE organization_id=$1 AND id=$2 FOR UPDATE"
    ).bind(identity.organization).bind(request_id).fetch_optional(&mut *tx).await?
        .ok_or(ReviewStoreError::NotFound)?;
    let initiator:String=row.try_get("initiator")?;
    let digest:String=row.try_get("intent_sha256")?;
    let required:i16=row.try_get("required_reviewers")?;
    let issued:i64=row.try_get("issued_at_unix")?;
    let expires:i64=row.try_get("expires_at_unix")?;
    if initiator==identity.account { return Err(ReviewStoreError::Unauthorized); }
    if digest!=hex::encode(expected_sha256) { return Err(ReviewStoreError::Conflict); }
    if now_unix<issued || now_unix>=expires { return Err(ReviewStoreError::Expired); }
    let existing:bool=sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM business_review_records \
         WHERE organization_id=$1 AND request_id=$2 AND reviewer=$3)"
    ).bind(identity.organization).bind(request_id).bind(&identity.account)
        .fetch_one(&mut *tx).await?;
    if existing { return Err(ReviewStoreError::AlreadyReviewed); }
    let count:i64=sqlx::query_scalar(
        "SELECT COUNT(*) FROM business_review_records \
         WHERE organization_id=$1 AND request_id=$2"
    ).bind(identity.organization).bind(request_id).fetch_one(&mut *tx).await?;
    if count>=i64::from(required) { return Err(ReviewStoreError::ReviewLimit); }
    sqlx::query(
        "INSERT INTO business_review_records \
         (organization_id,request_id,reviewer,recorded_at_unix) VALUES ($1,$2,$3,$4)"
    ).bind(identity.organization).bind(request_id).bind(&identity.account)
        .bind(now_unix).execute(&mut *tx).await?;
    tx.commit().await?;
    let updated=count+1;
    Ok(ReviewReceipt{
        count:updated, remaining:i64::from(required)-updated,
        review_count_met:updated>=i64::from(required),
        financial_execution_authorized:false,
    })
}

/// Real saved counts, not an approval or execution signal.
pub async fn read_review_count(
    pool: &PgPool,
    identity: &VerifiedIdentity,
    request_id: Uuid,
) -> Result<ReviewReceipt, ReviewStoreError> {
    if request_id.is_nil(){ return Err(ReviewStoreError::InvalidInput); }
    let mut tx=pool.begin().await?;
    locked_membership(&mut tx,identity,Permission::ReadAudit).await?;
    let required:Option<i16>=sqlx::query_scalar(
        "SELECT required_reviewers FROM business_review_requests \
         WHERE organization_id=$1 AND id=$2"
    ).bind(identity.organization).bind(request_id).fetch_optional(&mut *tx).await?;
    let required=required.ok_or(ReviewStoreError::NotFound)?;
    let count:i64=sqlx::query_scalar(
        "SELECT COUNT(*) FROM business_review_records WHERE organization_id=$1 AND request_id=$2"
    ).bind(identity.organization).bind(request_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(ReviewReceipt{
        count,remaining:(i64::from(required)-count).max(0),
        review_count_met:count>=i64::from(required),
        financial_execution_authorized:false,
    })
}
