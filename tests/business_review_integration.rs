//! Real PostgreSQL tenant isolation and maker-checker persistence tests.
//! All identities, digests, organizations and requests are isolated synthetic fixtures.
//! These tests do not assert wallet-signature verification or payout execution.

use sqlx::PgPool;
use stealthbridge_backend::{
    business_reviews::{
        create_request, create_canonical_request, read_review_count, record_review, CanonicalDraftRequest, ReviewStoreError,
    },
    org_auth::VerifiedIdentity,
    business_envelope::BusinessOperation,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const MAKER: &str = "GTESTMAKER000000001";
const APPROVER_A: &str = "GTESTAPPROVER0000001";
const APPROVER_B: &str = "GTESTAPPROVER0000002";
const VIEWER: &str = "GTESTVIEWER00000001";
const KEY: &str = "synthetic_business_request_0001";

fn identity(org: Uuid, account: &str) -> VerifiedIdentity {
    // Not a live signature; this function exercises an internal post-auth
    // database service. Separate org_auth tests cover signature verification.
    VerifiedIdentity {
        organization: org,
        account: account.to_owned(),
        domain: "staging.stealthbridge.example".to_owned(),
        authenticated_at_unix: NOW - 60,
    }
}
async fn fixture(pool: &PgPool, org: Uuid) {
    sqlx::query("INSERT INTO organizations(id,display_name,status) \
                 VALUES ($1,'TEST_ONLY_REVIEW_TENANT','active')")
        .bind(org).execute(pool).await.expect("fixture organization");
    for (account, role) in [
        (MAKER, "operator"),
        (APPROVER_A, "approver"),
        (APPROVER_B, "admin"),
        (VIEWER, "viewer"),
    ] {
        sqlx::query("INSERT INTO organization_members(organization_id,subject,role) \
                     VALUES ($1,$2,$3)")
            .bind(org).bind(account).bind(role).execute(pool).await
            .expect("fixture member");
    }
}
async fn cleanup(pool: &PgPool, org: Uuid) {
    sqlx::query("DELETE FROM business_review_records WHERE organization_id=$1")
        .bind(org).execute(pool).await.expect("cleanup records");
    sqlx::query("DELETE FROM business_review_requests WHERE organization_id=$1")
        .bind(org).execute(pool).await.expect("cleanup drafts");
    sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
        .bind(org).execute(pool).await.expect("cleanup members");
    sqlx::query("DELETE FROM organizations WHERE id=$1")
        .bind(org).execute(pool).await.expect("cleanup organization");
}

#[tokio::test]
async fn persisted_reviews_are_tenant_scoped_idempotent_and_never_authorize_payment() {
    let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool=PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
    let org=Uuid::new_v4();
    let another=Uuid::new_v4();
    fixture(&pool,org).await;
    fixture(&pool,another).await;

    let maker=identity(org,MAKER);
    let request=create_request(&pool,&maker,KEY,[11;32],2,NOW,3_600)
        .await.expect("create review request");
    assert!(request.created);
    let replay=create_request(&pool,&maker,KEY,[11;32],2,NOW+10,3_600)
        .await.expect("idempotent replay");
    assert!(!replay.created);
    assert_eq!(replay.id,request.id);
    assert!(matches!(
        create_request(&pool,&maker,KEY,[12;32],2,NOW,3_600).await,
        Err(ReviewStoreError::Conflict)
    ));

    // Tenant-scoped request ids cannot be read by a different organization's
    // otherwise valid viewer, even with the request UUID copied.
    assert!(matches!(
        read_review_count(&pool,&identity(another,VIEWER),request.id).await,
        Err(ReviewStoreError::NotFound)
    ));
    assert!(matches!(
        record_review(&pool,&identity(another,APPROVER_A),request.id,[11;32],NOW+15).await,
        Err(ReviewStoreError::NotFound)
    ));
    assert!(matches!(
        record_review(&pool,&maker,request.id,[11;32],NOW+15).await,
        Err(ReviewStoreError::Unauthorized)
    ));
    assert!(matches!(
        record_review(&pool,&identity(org,APPROVER_A),request.id,[12;32],NOW+15).await,
        Err(ReviewStoreError::Conflict)
    ));
    assert!(matches!(
        record_review(&pool,&identity(org,VIEWER),request.id,[11;32],NOW+15).await,
        Err(ReviewStoreError::Unauthorized)
    ));
    let first=record_review(&pool,&identity(org,APPROVER_A),request.id,[11;32],NOW+15)
        .await.expect("first reviewer");
    assert_eq!(first.count,1);
    assert_eq!(first.remaining,1);
    assert!(!first.review_count_met);
    assert!(!first.financial_execution_authorized);
    assert!(matches!(
        record_review(&pool,&identity(org,APPROVER_A),request.id,[11;32],NOW+30).await,
        Err(ReviewStoreError::AlreadyReviewed)
    ));
    let second=record_review(&pool,&identity(org,APPROVER_B),request.id,[11;32],NOW+45)
        .await.expect("second reviewer");
    assert_eq!(second.count,2);
    assert!(second.review_count_met);
    assert!(!second.financial_execution_authorized);

    let saved=read_review_count(&pool,&identity(org,VIEWER),request.id)
        .await.expect("persisted count");
    assert_eq!(saved.count,2);
    assert!(!saved.financial_execution_authorized);

    // Membership revocation applies to reads and reviews immediately.
    sqlx::query("UPDATE organization_members SET revoked_at=now() \
                 WHERE organization_id=$1 AND subject=$2")
        .bind(org).bind(VIEWER).execute(&pool).await.expect("revoke viewer");
    assert!(matches!(
        read_review_count(&pool,&identity(org,VIEWER),request.id).await,
        Err(ReviewStoreError::Unauthorized)
    ));

    cleanup(&pool,org).await;
    cleanup(&pool,another).await;
}


#[tokio::test]
async fn canonical_draft_digest_and_concurrent_reviewers_share_one_database_count() {
    let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool=PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
    let org=Uuid::new_v4();
    fixture(&pool,org).await;
    let (request,digest)=create_canonical_request(
        &pool,&identity(org,MAKER),CanonicalDraftRequest {
            operation:BusinessOperation::InvoiceReview,
            reference:"INVOICE_001",
            key:"canonical_business_request_0003",
            required_reviewers:2, now_unix:NOW, ttl_seconds:3_600,
        }
    ).await.expect("canonical request");
    let a=identity(org,APPROVER_A);
    let b=identity(org,APPROVER_B);
    let (first,second)=tokio::join!(
        record_review(&pool,&a,request.id,digest,NOW+20),
        record_review(&pool,&b,request.id,digest,NOW+20)
    );
    let first=first.expect("first concurrent reviewer");
    let second=second.expect("second concurrent reviewer");
    assert!(!first.financial_execution_authorized);
    assert!(!second.financial_execution_authorized);
    let counts=read_review_count(&pool,&identity(org,VIEWER),request.id)
        .await.expect("stable count");
    assert_eq!(counts.count,2);
    assert_eq!(counts.remaining,0);
    assert!(counts.review_count_met);
    assert!(!counts.financial_execution_authorized);
    cleanup(&pool,org).await;
}

#[tokio::test]
async fn expired_requests_and_suspended_tenants_cannot_collect_reviews() {
    let url=std::env::var("DATABASE_URL").expect("CI PostgreSQL required");
    let pool=PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
    let org=Uuid::new_v4();
    fixture(&pool,org).await;
    let request=create_request(
        &pool,&identity(org,MAKER),"review_second_fixture_0002",[9;32],2,NOW,300
    ).await.expect("create request");
    assert!(matches!(
        record_review(&pool,&identity(org,APPROVER_A),request.id,[9;32],NOW+300).await,
        Err(ReviewStoreError::Expired)
    ));
    sqlx::query("UPDATE organizations SET status='suspended' WHERE id=$1")
        .bind(org).execute(&pool).await.expect("suspend");
    assert!(matches!(
        record_review(&pool,&identity(org,APPROVER_A),request.id,[9;32],NOW+30).await,
        Err(ReviewStoreError::Unauthorized)
    ));
    cleanup(&pool,org).await;
}
