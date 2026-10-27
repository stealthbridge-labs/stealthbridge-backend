//! Private, read-only organization roster. Pending owners see only themselves.
//! Active organization owners/admins may inspect a bounded, paginated team.
//! This is not operator KYC, an invitation service, or payment authorization.
use crate::{server::AppState, wallet};
use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type AuthMac = Hmac<Sha256>;
const DOMAIN: &str = "stealthbridge-organization-team-v1";
const PAGE_SIZE: usize = 25;

#[derive(Serialize)]
struct TeamMember {
    account_address: String,
    role: String,
    joined_at_unix: i64,
}
#[derive(Serialize)]
struct TeamOrganization {
    id: Uuid,
    display_name: String,
    status: String,
    your_role: String,
}
#[derive(Serialize)]
struct TeamResponse {
    schema_version: u8,
    network: &'static str,
    source: &'static str,
    account_address: String,
    organization: TeamOrganization,
    members: Vec<TeamMember>,
    next_cursor: Option<String>,
    business_verified: bool,
    invitation_issuance_enabled: bool,
    payment_execution_enabled: bool,
    organization_payment_authorized: bool,
}

#[derive(Debug)]
enum TeamError {
    NotFound,
    Forbidden,
    InvalidRecord,
    Database(sqlx::Error),
}
impl From<sqlx::Error> for TeamError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

fn safe_cursor(raw: Option<&str>) -> Result<Option<&str>, TeamError> {
    match raw {
        None => Ok(None),
        Some(q) if q.starts_with("after=") && q.len() == 62 => {
            let address = &q[6..];
            if wallet::decode_account_address(address).is_none() {
                return Err(TeamError::InvalidRecord);
            }
            Ok(Some(address))
        }
        _ => Err(TeamError::InvalidRecord),
    }
}

fn verified_account(
    headers: &HeaderMap,
    secret: Option<&[u8]>,
    organization: Uuid,
    after: Option<&str>,
    now: i64,
) -> Option<String> {
    let secret = secret.filter(|value| value.len() >= 32)?;
    if organization.is_nil() {
        return None;
    }
    let account = headers.get("x-stealthbridge-account")?.to_str().ok()?;
    wallet::decode_account_address(account)?;
    let stamp = headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
    if stamp.is_empty() || stamp.len() > 12 || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let timestamp = stamp.parse::<i64>().ok()?;
    if timestamp <= 0 || timestamp > now + 5 || now.saturating_sub(timestamp) > 30 {
        return None;
    }
    let signature = headers.get("x-stealthbridge-signature")?.to_str().ok()?;
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let supplied = hex::decode(signature).ok()?;
    let path = format!(
        "/v1/account/organizations/{organization}/team{}",
        after
            .map(|cursor| format!("?after={cursor}"))
            .unwrap_or_default()
    );
    let signed = format!("{DOMAIN}\nGET\n{path}\n{account}\n{stamp}\n");
    let mut mac = AuthMac::new_from_slice(secret).ok()?;
    mac.update(signed.as_bytes());
    mac.verify_slice(&supplied).ok()?;
    Some(account.to_string())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

async fn read_team(
    pool: &PgPool,
    organization: Uuid,
    account: &str,
    after: Option<&str>,
) -> Result<TeamResponse, TeamError> {
    let membership = sqlx::query(
        r#"SELECT o.display_name, o.status, m.role
         FROM organizations o JOIN organization_members m
         ON m.organization_id = o.id
         WHERE o.id=$1 AND m.subject=$2 AND m.revoked_at IS NULL"#,
    )
    .bind(organization)
    .bind(account)
    .fetch_optional(pool)
    .await?
    .ok_or(TeamError::NotFound)?;

    let status: String = membership.try_get("status")?;
    let role: String = membership.try_get("role")?;
    let name: String = membership.try_get("display_name")?;
    let access = match (status.as_str(), role.as_str()) {
        ("pending", "owner") => false,
        ("active", "owner" | "admin") => true,
        ("pending" | "active", _) => return Err(TeamError::Forbidden),
        _ => return Err(TeamError::NotFound),
    };
    if name.trim().is_empty() || name.len() > 120 || name.trim() != name {
        return Err(TeamError::InvalidRecord);
    }

    // Pending team views intentionally exclude every other account, even if
    // an incorrectly inserted member row exists in the database.
    let records = sqlx::query(
        r#"SELECT m.subject, m.role,
          EXTRACT(EPOCH FROM m.created_at)::bigint AS joined_at_unix
          FROM organization_members m
          WHERE m.organization_id=$1 AND m.revoked_at IS NULL
          AND ($2::text IS NULL OR m.subject>$2)
          AND ($3::boolean OR m.subject=$4)
          ORDER BY m.subject LIMIT 26"#,
    )
    .bind(organization)
    .bind(after)
    .bind(access)
    .bind(account)
    .fetch_all(pool)
    .await?;
    let has_more = records.len() > PAGE_SIZE;
    let mut members = Vec::with_capacity(records.len().min(PAGE_SIZE));
    for row in records.into_iter().take(PAGE_SIZE) {
        let member: String = row.try_get("subject")?;
        let assigned_role: String = row.try_get("role")?;
        let joined: i64 = row.try_get("joined_at_unix")?;
        if wallet::decode_account_address(&member).is_none()
            || !matches!(
                assigned_role.as_str(),
                "owner" | "admin" | "operator" | "approver" | "viewer"
            )
            || joined <= 0
        {
            return Err(TeamError::InvalidRecord);
        }
        members.push(TeamMember {
            account_address: member,
            role: assigned_role,
            joined_at_unix: joined,
        });
    }
    let next_cursor = if has_more {
        members.last().map(|member| member.account_address.clone())
    } else {
        None
    };
    if !access
        && (has_more
            || members
                .iter()
                .any(|member| member.account_address != account))
    {
        return Err(TeamError::InvalidRecord);
    }
    Ok(TeamResponse {
        schema_version: 1,
        network: "testnet",
        source: "neon-organization-team",
        account_address: account.to_owned(),
        organization: TeamOrganization {
            id: organization,
            display_name: name,
            status,
            your_role: role,
        },
        members,
        next_cursor,
        business_verified: false,
        invitation_issuance_enabled: false,
        payment_execution_enabled: false,
        organization_payment_authorized: false,
    })
}

pub async fn get_organization_team(
    State(state): State<Arc<AppState>>,
    Path(organization): Path<Uuid>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let after = match safe_cursor(raw.as_deref()) {
        Ok(after) => after,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let secret = state
        .account_bridge_secret
        .as_ref()
        .map(|value| value.as_slice());
    if secret.is_none() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(account) = verified_account(&headers, secret, organization, after, unix_now()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(pool) = state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match tokio::time::timeout(
        Duration::from_secs(5),
        read_team(pool, organization, &account, after),
    )
    .await
    {
        Ok(Ok(mut team)) => {
            // A viewer-only invitation is possible after both activation and
            // the reviewed SQLx release flag; this is not payment authority.
            team.invitation_issuance_enabled = state.team_invites_enabled
                && team.organization.status == "active"
                && matches!(team.organization.your_role.as_str(), "owner" | "admin");
            (
                [
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("private, no-store"),
                    ),
                    (
                        header::X_CONTENT_TYPE_OPTIONS,
                        HeaderValue::from_static("nosniff"),
                    ),
                ],
                Json(team),
            )
                .into_response()
        }
        Ok(Err(TeamError::NotFound)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(TeamError::Forbidden)) => StatusCode::FORBIDDEN.into_response(),
        Ok(Err(TeamError::InvalidRecord)) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Ok(Err(TeamError::Database(error))) => {
            tracing::warn!(error = %error, "Organization team lookup unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Use a different CI public address from business_onboarding tests: the
    // latter intentionally caps pending applications per signer, and Rust
    // executes tests concurrently against the same ephemeral PostgreSQL.
    const OWNER: &str = "GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX";
    const OTHER: &str = "GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";

    fn signed_headers(
        secret: &[u8],
        org: Uuid,
        account: &str,
        time: i64,
        after: Option<&str>,
    ) -> HeaderMap {
        let stamp = time.to_string();
        let path = format!(
            "/v1/account/organizations/{org}/team{}",
            after
                .map(|value| format!("?after={value}"))
                .unwrap_or_default()
        );
        let signed = format!("{DOMAIN}\nGET\n{path}\n{account}\n{stamp}\n");
        let mut mac = AuthMac::new_from_slice(secret).unwrap();
        mac.update(signed.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-stealthbridge-account",
            HeaderValue::from_str(account).unwrap(),
        );
        headers.insert(
            "x-stealthbridge-issued-at",
            HeaderValue::from_str(&stamp).unwrap(),
        );
        headers.insert(
            "x-stealthbridge-signature",
            HeaderValue::from_str(&hex::encode(mac.finalize().into_bytes())).unwrap(),
        );
        headers
    }

    #[test]
    fn tenant_bound_signature_rejects_cross_organization_queries_and_expiry() {
        let key = b"test-only-long-account-attestation-secret-12345";
        let org = Uuid::new_v4();
        let time = 1_800_000_000;
        let signed = signed_headers(key, org, OWNER, time, None);
        assert_eq!(
            verified_account(&signed, Some(key), org, None, time),
            Some(OWNER.into())
        );
        assert!(verified_account(&signed, Some(key), Uuid::new_v4(), None, time).is_none());
        assert!(verified_account(&signed, Some(key), org, Some(OTHER), time).is_none());
        assert!(verified_account(&signed, Some(key), org, None, time + 31).is_none());
        assert!(verified_account(&signed, Some(b"short"), org, None, time).is_none());
        assert!(verified_account(&signed, Some(key), Uuid::nil(), None, time).is_none());
        let signed_page = signed_headers(key, org, OWNER, time, Some(OTHER));
        assert_eq!(
            verified_account(&signed_page, Some(key), org, Some(OTHER), time),
            Some(OWNER.into())
        );
        assert_eq!(
            safe_cursor(Some(&format!("after={OTHER}"))).unwrap(),
            Some(OTHER)
        );
        for bad in ["", "after=", "after=not-wallet", "foo=1", "after=x&after=y"] {
            assert!(safe_cursor(Some(bad)).is_err());
        }
    }

    #[tokio::test]
    async fn real_ci_postgres_isolates_pending_and_revoked_members() {
        let url = std::env::var("DATABASE_URL").expect("CI PostgreSQL is required");
        let pool = PgPool::connect(&url).await.expect("CI DB");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate");
        let org = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,display_name,status) VALUES ($1,'CI TEAM ONLY','pending')")
            .bind(org).execute(&pool).await.unwrap();
        for (account, role) in [(OWNER, "owner"), (OTHER, "viewer")] {
            sqlx::query(
                "INSERT INTO organization_members(organization_id,subject,role) VALUES($1,$2,$3)",
            )
            .bind(org)
            .bind(account)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
        }
        let pending = read_team(&pool, org, OWNER, None).await.unwrap();
        assert_eq!(pending.organization.status, "pending");
        assert_eq!(pending.members.len(), 1);
        assert_eq!(pending.members[0].account_address, OWNER);
        assert!(!pending.business_verified);
        assert!(!pending.organization_payment_authorized);
        assert!(matches!(
            read_team(&pool, org, OTHER, None).await,
            Err(TeamError::Forbidden)
        ));
        sqlx::query("UPDATE organizations SET status='active' WHERE id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        let active = read_team(&pool, org, OWNER, None).await.unwrap();
        assert_eq!(active.members.len(), 2);
        assert_eq!(active.organization.status, "active");
        assert!(
            !active.business_verified,
            "active status never implies legal verification"
        );
        assert!(matches!(
            read_team(&pool, org, OTHER, None).await,
            Err(TeamError::Forbidden)
        ));
        sqlx::query("UPDATE organization_members SET revoked_at=now() WHERE organization_id=$1 AND subject=$2")
            .bind(org).bind(OTHER).execute(&pool).await.unwrap();
        let after_revocation = read_team(&pool, org, OWNER, None).await.unwrap();
        assert_eq!(after_revocation.members.len(), 1);
        sqlx::query("UPDATE organizations SET status='suspended' WHERE id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            read_team(&pool, org, OWNER, None).await,
            Err(TeamError::NotFound)
        ));
        sqlx::query("DELETE FROM organization_members WHERE organization_id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id=$1")
            .bind(org)
            .execute(&pool)
            .await
            .unwrap();
    }
}
