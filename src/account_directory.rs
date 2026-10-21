//! Authenticated, read-only directory of a real wallet's active organization
//! memberships. The user-facing app MUST verify the user's session BEFORE
//! issuing a short-lived backend attestation. No organization data is public.
use axum::{extract::State,http::{header,HeaderMap,HeaderValue,StatusCode},response::{IntoResponse,Response},Json};
use hmac::{Hmac,Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::{PgPool,Row};
use std::{sync::Arc,time::{SystemTime,UNIX_EPOCH}};
use uuid::Uuid;
use crate::{server::AppState,wallet};

type HmacSha256=Hmac<Sha256>;
const DOMAIN:&str="stealthbridge-account-directory-v1\nGET\n/v1/account/directory\n";
const MAX_MEMBER_ROWS:usize=25;

#[derive(Debug,Serialize)]
pub struct OrganizationMembership {
    id:Uuid,
    display_name:String,
    role:String,
}

#[derive(Debug,Serialize)]
pub struct AccountDirectory {
    schema_version:u8,
    network:&'static str,
    source:&'static str,
    account_address:String,
    organizations:Vec<OrganizationMembership>,
    has_more:bool,
    payment_execution_enabled:bool,
    organization_payment_authorized:bool,
}

fn authenticated_account(headers:&HeaderMap,secret:Option<&[u8]>,now:i64)->Option<String>{
    let secret=secret.filter(|secret|secret.len()>=32)?;
    let account=headers.get("x-stealthbridge-account")?.to_str().ok()?;
    if account.len()!=56||wallet::decode_account_address(account).is_none(){return None;}
    let when=headers.get("x-stealthbridge-issued-at")?.to_str().ok()?;
    if when.is_empty()||when.len()>12||!when.bytes().all(|b|b.is_ascii_digit()){return None;}
    let epoch=when.parse::<i64>().ok()?;
    if epoch<=0||epoch>now+5||now.saturating_sub(epoch)>30{return None;}
    let signature=headers.get("x-stealthbridge-signature")?.to_str().ok()?;
    if signature.len()!=64||!signature.bytes().all(|b|b.is_ascii_hexdigit()){return None;}
    let supplied=hex::decode(signature).ok()?;
    let mut mac=HmacSha256::new_from_slice(secret).ok()?;
    mac.update(format!("{DOMAIN}{account}\n{when}\n").as_bytes());
    mac.verify_slice(&supplied).ok()?;
    Some(account.to_owned())
}

async fn member_rows(pool:&PgPool,account:&str)->Result<(Vec<OrganizationMembership>,bool),sqlx::Error>{
    // The signer identity comes ONLY from a validated attestation, never an
    // arbitrary path parameter or query string. Suspended tenants and
    // revoked members must never appear in the customer directory.
    let rows=sqlx::query(
        r#"SELECT o.id,o.display_name,m.role FROM organization_members m
           INNER JOIN organizations o ON o.id=m.organization_id
           WHERE m.subject=$1 AND m.revoked_at IS NULL AND o.status='active'
           ORDER BY o.created_at,o.id LIMIT 26"#
    ).bind(account).fetch_all(pool).await?;
    let has_more=rows.len()>MAX_MEMBER_ROWS;
    let mut organizations=Vec::with_capacity(rows.len().min(MAX_MEMBER_ROWS));
    for row in rows.into_iter().take(MAX_MEMBER_ROWS) {
        let role:String=row.try_get("role")?;
        if !["owner","admin","operator","approver","viewer"].contains(&role.as_str()){
            // Unknown role must never masquerade as verified membership.
            continue;
        }
        let display_name:String=row.try_get("display_name")?;
        if display_name.trim().is_empty()||display_name.len()>120{return Err(sqlx::Error::RowNotFound);}
        organizations.push(OrganizationMembership{
            id:row.try_get("id")?,display_name,role
        });
    }
    Ok((organizations,has_more))
}

pub async fn account_directory(
    State(state):State<Arc<AppState>>,
    headers:HeaderMap,
)->Response{
    let now=SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration|duration.as_secs() as i64).unwrap_or(0);
    let secret=state.account_bridge_secret.as_ref().map(|s|s.as_slice());
    if secret.is_none(){return StatusCode::SERVICE_UNAVAILABLE.into_response();}
    let Some(account)=authenticated_account(&headers,secret,now) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(pool)=state.db.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let result=tokio::time::timeout(std::time::Duration::from_secs(4),member_rows(pool,&account)).await;
    match result {
        Ok(Ok((organizations,has_more)))=>(
            [(header::CACHE_CONTROL,HeaderValue::from_static("private, no-store")),
             (header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff"))],
            Json(AccountDirectory{
                schema_version:1,network:"testnet",source:"neon-active-memberships",
                account_address:account,organizations,has_more,
                payment_execution_enabled:false,organization_payment_authorized:false
            })
        ).into_response(),
        _=>StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn signed_internal_attestation_is_account_bound_fresh_and_deny_by_default(){
        let secret=b"0123456789abcdef0123456789abcdef123456789";
        let address="GC3YRVLB7IN7SNUYVWFUC6OD3QWJXCUZ4HOBNIPVGY7BZDVOYMDNX5TN";
        let now=1_800_000_000_i64;
        let stamp=(now-5).to_string();
        let mut mac=HmacSha256::new_from_slice(secret).unwrap();
        mac.update(format!("{DOMAIN}{address}\n{stamp}\n").as_bytes());
        let sig=hex::encode(mac.finalize().into_bytes());
        let mut headers=HeaderMap::new();
        headers.insert("x-stealthbridge-account",HeaderValue::from_str(address).unwrap());
        headers.insert("x-stealthbridge-issued-at",HeaderValue::from_str(&stamp).unwrap());
        headers.insert("x-stealthbridge-signature",HeaderValue::from_str(&sig).unwrap());
        assert_eq!(authenticated_account(&headers,Some(secret),now),Some(address.to_owned()));
        assert_eq!(authenticated_account(&headers,Some(secret),now+31),None);
        assert_eq!(authenticated_account(&headers,None,now),None);
        assert_eq!(authenticated_account(&headers,Some(b"short"),now),None);
        let mut forged=headers.clone();
        forged.insert("x-stealthbridge-account",HeaderValue::from_static("GA23INVALID"));
        assert_eq!(authenticated_account(&forged,Some(secret),now),None);
        let mut altered=headers.clone();
        altered.insert("x-stealthbridge-issued-at",HeaderValue::from_static("1800000000"));
        assert_eq!(authenticated_account(&altered,Some(secret),now),None);
        let mut tampered=headers.clone();
        tampered.insert("x-stealthbridge-signature",HeaderValue::from_static("0000000000000000000000000000000000000000000000000000000000000000"));
        assert_eq!(authenticated_account(&tampered,Some(secret),now),None);
    }
}
