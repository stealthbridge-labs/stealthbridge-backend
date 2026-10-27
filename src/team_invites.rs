//! Opt-in Testnet viewer invitations. Feature gated until protected SQLx release.
//! No business KYC, payment privilege, wallet transaction or email collection.
use crate::{server::AppState, wallet};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type AuthMac = Hmac<Sha256>;
const PATH: &str = "/v1/account/team-invites";
const DOMAIN: &str = "stealthbridge-team-invites-v1";
const PAGE: usize = 20;
const MAX_OPEN: i64 = 10;

#[derive(Serialize)]
struct InviteRecord {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    peer_address: String,
    role: &'static str,
    status: String,
    created_at_unix: i64,
    expires_at_unix: i64,
}
#[derive(Serialize)]
struct InviteDirectory {
    schema_version: u8,
    network: &'static str,
    source: &'static str,
    account_address: String,
    received: Vec<InviteRecord>,
    sent: Vec<InviteRecord>,
    received_more: bool,
    sent_more: bool,
    business_verified: bool,
    payment_execution_enabled: bool,
    organization_payment_authorized: bool,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum InviteAction {
    Create {
        organization_id: Uuid,
        invited_account: String,
        role: String,
    },
    Accept {
        invitation_id: Uuid,
    },
    Revoke {
        invitation_id: Uuid,
    },
}
#[derive(Debug)]
enum InviteError {
    Denied,
    Conflict,
    Invalid,
    Database(sqlx::Error),
}
impl From<sqlx::Error> for InviteError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs() as i64)
        .unwrap_or(0)
}
fn verify(
    headers: &HeaderMap,
    secret: Option<&[u8]>,
    method: &str,
    request_id: &str,
    digest: &str,
    now: i64,
) -> Option<String> {
    let secret = secret.filter(|key| key.len() >= 32)?;
    let account = headers.get("x-stealthbridge-account")?.to_str().ok()?;
    wallet::decode_account_address(account)?;
    let stamp = headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
    if stamp.is_empty() || stamp.len() > 12 || !stamp.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    let issued = stamp.parse::<i64>().ok()?;
    if issued <= 0 || issued > now + 5 || now.saturating_sub(issued) > 30 {
        return None;
    }
    let sig = headers.get("x-stealthbridge-signature")?.to_str().ok()?;
    if sig.len() != 64 || !sig.bytes().all(|x| x.is_ascii_hexdigit()) {
        return None;
    }
    let decoded = hex::decode(sig).ok()?;
    let payload =
        format!("{DOMAIN}\n{method}\n{PATH}\n{account}\n{stamp}\n{request_id}\n{digest}\n");
    let mut mac = AuthMac::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&decoded).ok()?;
    Some(account.to_owned())
}
fn secret(state: &AppState) -> Option<&[u8]> {
    state
        .account_bridge_secret
        .as_ref()
        .map(|value| value.as_slice())
}
fn record(row: &sqlx::postgres::PgRow, peer: &str) -> Result<InviteRecord, InviteError> {
    let address: String = row.try_get(peer)?;
    if wallet::decode_account_address(&address).is_none() {
        return Err(InviteError::Invalid);
    }
    let status: String = row.try_get("invite_status")?;
    if !matches!(
        status.as_str(),
        "pending" | "expired" | "revoked" | "accepted"
    ) {
        return Err(InviteError::Invalid);
    }
    let name: String = row.try_get("display_name")?;
    if name.trim().is_empty() || name.len() > 120 {
        return Err(InviteError::Invalid);
    }
    let created: i64 = row.try_get("created_at_unix")?;
    let expires: i64 = row.try_get("expires_at_unix")?;
    if created <= 0 || expires <= created {
        return Err(InviteError::Invalid);
    }
    Ok(InviteRecord {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        organization_name: name,
        peer_address: address,
        role: "viewer",
        status,
        created_at_unix: created,
        expires_at_unix: expires,
    })
}
async fn list(pool: &PgPool, account: &str) -> Result<InviteDirectory, InviteError> {
    let received = sqlx::query(
        r#"SELECT i.id,i.organization_id,o.display_name,i.invited_by,
    EXTRACT(EPOCH FROM i.created_at)::bigint created_at_unix,
    EXTRACT(EPOCH FROM i.expires_at)::bigint expires_at_unix,
    'pending'::text invite_status
   FROM organization_invitations i
   JOIN organizations o ON o.id=i.organization_id
   JOIN organization_members m ON m.organization_id=o.id AND m.subject=i.invited_by
    AND m.revoked_at IS NULL AND m.role IN ('owner','admin')
   WHERE i.invited_account=$1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL
    AND i.expires_at>now() AND o.status='active'
   ORDER BY i.created_at DESC,i.id DESC LIMIT 21"#,
    )
    .bind(account)
    .fetch_all(pool)
    .await?;
    let sent = sqlx::query(
        r#"SELECT i.id,i.organization_id,o.display_name,i.invited_account,
    EXTRACT(EPOCH FROM i.created_at)::bigint created_at_unix,
    EXTRACT(EPOCH FROM i.expires_at)::bigint expires_at_unix,
    CASE WHEN i.accepted_at IS NOT NULL THEN 'accepted'
         WHEN i.expires_at<=now() THEN 'expired'
         WHEN i.revoked_at IS NOT NULL THEN 'revoked'
         ELSE 'pending' END::text invite_status
   FROM organization_invitations i
   JOIN organizations o ON o.id=i.organization_id
   JOIN organization_members m ON m.organization_id=o.id
   WHERE m.subject=$1 AND m.role IN ('owner','admin')
    AND m.revoked_at IS NULL AND o.status='active'
   ORDER BY i.created_at DESC,i.id DESC LIMIT 21"#,
    )
    .bind(account)
    .fetch_all(pool)
    .await?;
    let received_more = received.len() > PAGE;
    let sent_more = sent.len() > PAGE;
    Ok(InviteDirectory {
        schema_version: 1,
        network: "testnet",
        source: "neon-team-invitations",
        account_address: account.to_owned(),
        received: received
            .iter()
            .take(PAGE)
            .map(|r| record(r, "invited_by"))
            .collect::<Result<_, _>>()?,
        sent: sent
            .iter()
            .take(PAGE)
            .map(|r| record(r, "invited_account"))
            .collect::<Result<_, _>>()?,
        received_more,
        sent_more,
        business_verified: false,
        payment_execution_enabled: false,
        organization_payment_authorized: false,
    })
}
async fn require_manager(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org: Uuid,
    account: &str,
) -> Result<(), InviteError> {
    let status =
        sqlx::query_scalar::<_, String>("SELECT status FROM organizations WHERE id=$1 FOR UPDATE")
            .bind(org)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(InviteError::Denied)?;
    if status != "active" {
        return Err(InviteError::Denied);
    }
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM organization_members WHERE organization_id=$1 AND subject=$2
   AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(org)
    .bind(account)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(InviteError::Denied)?;
    if role != "owner" && role != "admin" {
        return Err(InviteError::Denied);
    }
    Ok(())
}
async fn apply(
    pool: &PgPool,
    account: &str,
    request_id: Uuid,
    action: InviteAction,
) -> Result<(), InviteError> {
    let mut tx = pool.begin().await?;
    match action {
        InviteAction::Create {
            organization_id,
            invited_account,
            role,
        } => {
            if organization_id.is_nil()
                || wallet::decode_account_address(&invited_account).is_none()
                || invited_account == account
                || role != "viewer"
            {
                return Err(InviteError::Invalid);
            }
            require_manager(&mut tx, organization_id, account).await?;
            // Account could have been revoked, or have active membership. Do not
            // use a pre-existing invitation to resurrect a revoked account.
            let existing: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM organization_members WHERE organization_id=$1
     AND subject=$2)",
            )
            .bind(organization_id)
            .bind(&invited_account)
            .fetch_one(&mut *tx)
            .await?;
            if existing {
                return Err(InviteError::Conflict);
            }
            sqlx::query(
                "UPDATE organization_invitations SET revoked_at=now()
     WHERE organization_id=$1 AND invited_account=$2
     AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at<=now()",
            )
            .bind(organization_id)
            .bind(&invited_account)
            .execute(&mut *tx)
            .await?;
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM organization_invitations WHERE organization_id=$1
     AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()",
            )
            .bind(organization_id)
            .fetch_one(&mut *tx)
            .await?;
            if count >= MAX_OPEN {
                return Err(InviteError::Conflict);
            }
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM organization_invitations WHERE organization_id=$1
     AND invited_account=$2 AND accepted_at IS NULL AND revoked_at IS NULL)",
            )
            .bind(organization_id)
            .bind(&invited_account)
            .fetch_one(&mut *tx)
            .await?;
            if exists {
                return Err(InviteError::Conflict);
            }
            sqlx::query(
                "INSERT INTO organization_invitations
     (id,organization_id,invited_account,invited_by,role,expires_at)
     VALUES($1,$2,$3,$4,'viewer',now()+INTERVAL '7 days')",
            )
            .bind(request_id)
            .bind(organization_id)
            .bind(&invited_account)
            .bind(account)
            .execute(&mut *tx)
            .await?;
        }
        InviteAction::Accept { invitation_id } => {
            if invitation_id.is_nil() {
                return Err(InviteError::Invalid);
            }
            // Resolve org before locking. Then lock organization first, invitation
            // second to keep lock ordering consistent with create/revoke.
            let org: Uuid = sqlx::query_scalar(
                "SELECT organization_id FROM organization_invitations WHERE id=$1",
            )
            .bind(invitation_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(InviteError::Denied)?;
            let active: String =
                sqlx::query_scalar("SELECT status FROM organizations WHERE id=$1 FOR UPDATE")
                    .bind(org)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(InviteError::Denied)?;
            if active != "active" {
                return Err(InviteError::Denied);
            }
            let row = sqlx::query(
                "SELECT invited_account,invited_by,role,
     (accepted_at IS NOT NULL) AS accepted,
     (revoked_at IS NOT NULL) AS revoked
     FROM organization_invitations WHERE id=$1 AND organization_id=$2 FOR UPDATE",
            )
            .bind(invitation_id)
            .bind(org)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(InviteError::Denied)?;
            let invited: String = row.try_get("invited_account")?;
            let inviter: String = row.try_get("invited_by")?;
            let role: String = row.try_get("role")?;
            if invited != account
                || role != "viewer"
                || row.try_get::<bool, _>("accepted")?
                || row.try_get::<bool, _>("revoked")?
            {
                return Err(InviteError::Denied);
            }
            let valid: bool = sqlx::query_scalar(
                "SELECT expires_at>now() FROM organization_invitations WHERE id=$1",
            )
            .bind(invitation_id)
            .fetch_one(&mut *tx)
            .await?;
            if !valid {
                return Err(InviteError::Denied);
            }
            let owner = sqlx::query_scalar::<_, String>(
                "SELECT role FROM organization_members WHERE organization_id=$1 AND subject=$2
     AND revoked_at IS NULL FOR UPDATE",
            )
            .bind(org)
            .bind(inviter)
            .fetch_optional(&mut *tx)
            .await?;
            if !matches!(owner.as_deref(), Some("owner" | "admin")) {
                return Err(InviteError::Denied);
            }
            let written = sqlx::query(
                "INSERT INTO organization_members(organization_id,subject,role)
     VALUES($1,$2,'viewer') ON CONFLICT DO NOTHING",
            )
            .bind(org)
            .bind(account)
            .execute(&mut *tx)
            .await?;
            if written.rows_affected() != 1 {
                return Err(InviteError::Conflict);
            }
            let updated = sqlx::query(
                "UPDATE organization_invitations SET accepted_at=now()
     WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()",
            )
            .bind(invitation_id)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(InviteError::Conflict);
            }
        }
        InviteAction::Revoke { invitation_id } => {
            if invitation_id.is_nil() {
                return Err(InviteError::Invalid);
            }
            let org: Uuid = sqlx::query_scalar(
                "SELECT organization_id FROM organization_invitations WHERE id=$1",
            )
            .bind(invitation_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(InviteError::Denied)?;
            require_manager(&mut tx, org, account).await?;
            let updated = sqlx::query(
                "UPDATE organization_invitations SET revoked_at=now()
     WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL
      AND revoked_at IS NULL AND expires_at>now()",
            )
            .bind(invitation_id)
            .bind(org)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(InviteError::Conflict);
            }
        }
    }
    tx.commit().await?;
    Ok(())
}
fn error_response(error: InviteError) -> Response {
    match error {
        InviteError::Denied => StatusCode::FORBIDDEN.into_response(),
        InviteError::Conflict => StatusCode::CONFLICT.into_response(),
        InviteError::Invalid => StatusCode::BAD_REQUEST.into_response(),
        InviteError::Database(err) => {
            tracing::warn!(error=%err,"invitation storage unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
pub async fn get_invites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.team_invites_enabled {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(account) = verify(&headers, secret(&state), "GET", "", "", now_unix()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(Duration::from_secs(5), list(db, &account)).await {
        Ok(Ok(rows)) => (
            [(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private,no-store"),
            )],
            Json(rows),
        )
            .into_response(),
        Ok(Err(err)) => error_response(err),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
pub async fn post_invites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.team_invites_enabled {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if body.is_empty() || body.len() > 400 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(request_id) = headers
        .get("x-stealthbridge-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|id| !id.is_nil())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let digest = hex::encode(Sha256::digest(&body));
    let Some(account) = verify(
        &headers,
        secret(&state),
        "POST",
        &request_id.to_string(),
        &digest,
        now_unix(),
    ) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(action) = serde_json::from_slice::<InviteAction>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(db) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(7),
        apply(db, &account, request_id, action),
    )
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => error_response(error),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const ADDRESS: &str = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
    #[test]
    fn signatures_lock_method_account_nonce_and_digest() {
        let secret = b"CI-test-only-team-invite-secret-1234567890";
        let ts = 1_800_000_000_i64;
        let nonce = Uuid::new_v4().to_string();
        let digest = "a".repeat(64);
        let data = format!("{DOMAIN}\nPOST\n{PATH}\n{ADDRESS}\n{ts}\n{nonce}\n{digest}\n");
        let mut mac = AuthMac::new_from_slice(secret).unwrap();
        mac.update(data.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert("x-stealthbridge-account", HeaderValue::from_static(ADDRESS));
        headers.insert(
            "x-stealthbridge-issued-at",
            HeaderValue::from_str(&ts.to_string()).unwrap(),
        );
        headers.insert(
            "x-stealthbridge-signature",
            HeaderValue::from_str(&hex::encode(mac.finalize().into_bytes())).unwrap(),
        );
        assert_eq!(
            verify(&headers, Some(secret), "POST", &nonce, &digest, ts),
            Some(ADDRESS.to_string())
        );
        assert!(verify(&headers, Some(secret), "GET", &nonce, &digest, ts).is_none());
        assert!(verify(&headers, Some(secret), "POST", &nonce, "different", ts).is_none());
        assert!(verify(&headers, Some(secret), "POST", "different", &digest, ts).is_none());
        assert!(verify(&headers, Some(secret), "POST", &nonce, &digest, ts + 31).is_none());
    }
    #[test]
    fn strict_invite_payload_disallows_admin_and_unknown_fields() {
        assert!(serde_json::from_str::<InviteAction>(
   r#"{"action":"create","organization_id":"9a1a395f-249c-4907-b657-d48df4b38d28","invited_account":"GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN","role":"viewer"}"#).is_ok());
        assert!(serde_json::from_str::<InviteAction>(
   r#"{"action":"accept","invitation_id":"9a1a395f-249c-4907-b657-d48df4b38d28","role":"owner"}"#).is_err());
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    const OWNER: &str = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
    const TARGET: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
    const OUTSIDER: &str = "GBBCOFZZ3RDQHTC662EVM3UO5SAXQEZB6DL64HLEJYEYJ4KBVL3CDLTE";
    #[tokio::test]
    async fn invitations_require_active_manager_consent_and_one_time_viewer_acceptance() {
        let url = std::env::var("DATABASE_URL").expect("isolated GitHub CI postgres");
        let db = PgPool::connect(&url).await.expect("CI DB");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("CI migrations");
        for account in [OWNER, TARGET, OUTSIDER] {
            assert!(wallet::decode_account_address(account).is_some());
        }
        let org = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES($1,'CI INVITATIONS ONLY','pending')")
   .bind(org).execute(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,'owner')",
        )
        .bind(org)
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();
        let invite = Uuid::new_v4();
        let action = || InviteAction::Create {
            organization_id: org,
            invited_account: TARGET.to_string(),
            role: "viewer".to_string(),
        };
        assert!(matches!(
            apply(&db, OWNER, invite, action()).await,
            Err(InviteError::Denied)
        ));
        sqlx::query("UPDATE organizations SET status='active' WHERE id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
        assert!(matches!(
            apply(&db, OUTSIDER, invite, action()).await,
            Err(InviteError::Denied)
        ));
        assert!(matches!(
            apply(
                &db,
                OWNER,
                Uuid::new_v4(),
                InviteAction::Create {
                    organization_id: org,
                    invited_account: TARGET.to_string(),
                    role: "admin".into()
                }
            )
            .await,
            Err(InviteError::Invalid)
        ));
        apply(&db, OWNER, invite, action())
            .await
            .expect("create viewer invitation");
        assert!(matches!(
            apply(&db, OWNER, Uuid::new_v4(), action()).await,
            Err(InviteError::Conflict)
        ));
        let owner_list = list(&db, OWNER).await.unwrap();
        assert!(owner_list
            .sent
            .iter()
            .any(|item| item.id == invite && item.status == "pending"));
        let target_list = list(&db, TARGET).await.unwrap();
        assert!(target_list
            .received
            .iter()
            .any(|item| item.id == invite && item.role == "viewer"));
        assert!(list(&db, OUTSIDER).await.unwrap().received.is_empty());
        assert!(matches!(
            apply(
                &db,
                OUTSIDER,
                Uuid::new_v4(),
                InviteAction::Accept {
                    invitation_id: invite
                }
            )
            .await,
            Err(InviteError::Denied)
        ));
        apply(
            &db,
            TARGET,
            Uuid::new_v4(),
            InviteAction::Accept {
                invitation_id: invite,
            },
        )
        .await
        .expect("signed recipient accepts only once");
        assert!(matches!(
            apply(
                &db,
                TARGET,
                Uuid::new_v4(),
                InviteAction::Accept {
                    invitation_id: invite
                }
            )
            .await,
            Err(InviteError::Denied)
        ));
        let role: String = sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE organization_id=$1 AND subject=$2",
        )
        .bind(org)
        .bind(TARGET)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(role, "viewer");
        assert!(!list(&db, TARGET)
            .await
            .unwrap()
            .received
            .iter()
            .any(|item| item.id == invite));
        assert!(list(&db, OWNER)
            .await
            .unwrap()
            .sent
            .iter()
            .any(|item| item.id == invite && item.status == "accepted"));
        assert!(matches!(
            apply(
                &db,
                TARGET,
                Uuid::new_v4(),
                InviteAction::Create {
                    organization_id: org,
                    invited_account: OUTSIDER.to_string(),
                    role: "viewer".to_string()
                }
            )
            .await,
            Err(InviteError::Denied)
        ));
        assert!(matches!(
            apply(
                &db,
                OWNER,
                Uuid::new_v4(),
                InviteAction::Revoke {
                    invitation_id: invite
                }
            )
            .await,
            Err(InviteError::Conflict)
        ));
        // Existing membership (even if subsequently revoked) cannot be
        // silently resurrected via an old or newly created invitation.
        sqlx::query("UPDATE organization_members SET revoked_at=now() WHERE organization_id=$1 AND subject=$2")
   .bind(org).bind(TARGET).execute(&db).await.unwrap();
        assert!(matches!(
            apply(&db, OWNER, Uuid::new_v4(), action()).await,
            Err(InviteError::Conflict)
        ));
        sqlx::query("DELETE FROM organization_invitations WHERE organization_id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn revocation_expiry_and_inviter_revocation_block_acceptance() {
        let url = std::env::var("DATABASE_URL").expect("isolated CI postgres");
        let db = PgPool::connect(&url).await.expect("CI postgres");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("migrations");
        let org = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES($1,'CI REVOCATION ONLY','active')")
   .bind(org).execute(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,'owner')",
        )
        .bind(org)
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();
        let create = || InviteAction::Create {
            organization_id: org,
            invited_account: TARGET.to_string(),
            role: "viewer".to_string(),
        };
        let one = Uuid::new_v4();
        apply(&db, OWNER, one, create()).await.unwrap();
        apply(
            &db,
            OWNER,
            Uuid::new_v4(),
            InviteAction::Revoke { invitation_id: one },
        )
        .await
        .unwrap();
        assert!(matches!(
            apply(
                &db,
                TARGET,
                Uuid::new_v4(),
                InviteAction::Accept { invitation_id: one }
            )
            .await,
            Err(InviteError::Denied)
        ));
        let two = Uuid::new_v4();
        apply(&db, OWNER, two, create()).await.unwrap();
        sqlx::query(
            "UPDATE organization_invitations
   SET created_at=now()-INTERVAL '8 days',expires_at=now()-INTERVAL '1 day'
   WHERE id=$1",
        )
        .bind(two)
        .execute(&db)
        .await
        .unwrap();
        assert!(matches!(
            apply(
                &db,
                TARGET,
                Uuid::new_v4(),
                InviteAction::Accept { invitation_id: two }
            )
            .await,
            Err(InviteError::Denied)
        ));
        let three = Uuid::new_v4();
        apply(&db, OWNER, three, create()).await.unwrap();
        sqlx::query(
            "UPDATE organization_members SET revoked_at=now()
    WHERE organization_id=$1 AND subject=$2",
        )
        .bind(org)
        .bind(OWNER)
        .execute(&db)
        .await
        .unwrap();
        assert!(list(&db, TARGET).await.unwrap().received.is_empty());
        assert!(matches!(
            apply(
                &db,
                TARGET,
                Uuid::new_v4(),
                InviteAction::Accept {
                    invitation_id: three
                }
            )
            .await,
            Err(InviteError::Denied)
        ));
        sqlx::query("DELETE FROM organization_invitations WHERE organization_id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org)
            .execute(&db)
            .await
            .unwrap();
    }
}
