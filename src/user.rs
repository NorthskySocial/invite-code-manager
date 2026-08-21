use crate::db::fetch_invite_code_admin;
use crate::{DbConn, error::AppError};
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::ToSchema;

#[derive(Queryable, Selectable, Clone, Debug, Deserialize, Serialize, Insertable, ToSchema)]
#[diesel(table_name = crate::schema::invite_code_admin)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InviteCodeAdmin {
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
    pub otp_enabled: i32,
    pub otp_verified: i32,
}

impl<S> FromRequestParts<S> for InviteCodeAdmin
where
    DbConn: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;

        let username: String = session
            .get("username")
            .await
            .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?
            .ok_or_else(|| AppError::AuthError("Not logged in".to_string()))?;

        let db_pool = DbConn::from_ref(state);

        let admin = fetch_invite_code_admin(&db_pool, &username)
            .await
            .ok_or_else(|| AppError::AuthError("User not found".to_string()))?;

        if admin.otp_verified == 1 {
            let otp_validated: Option<String> = session
                .get("otp_validated")
                .await
                .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;

            if otp_validated.as_deref() != Some("y") {
                return Err(AppError::AuthError("2FA required".to_string()));
            }
        }

        Ok(admin)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InviteCodeAdminPreLogin {
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
    pub otp_enabled: i32,
    pub otp_verified: i32,
}

impl From<InviteCodeAdmin> for InviteCodeAdminPreLogin {
    fn from(admin: InviteCodeAdmin) -> Self {
        Self {
            username: admin.username,
            password: admin.password,
            otp_base32: admin.otp_base32,
            otp_auth_url: admin.otp_auth_url,
            otp_enabled: admin.otp_enabled,
            otp_verified: admin.otp_verified,
        }
    }
}

impl<S> FromRequestParts<S> for InviteCodeAdminPreLogin
where
    DbConn: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;

        let username: String = session
            .get("username")
            .await
            .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?
            .ok_or_else(|| AppError::AuthError("Not logged in".to_string()))?;

        let db_pool = DbConn::from_ref(state);

        let admin = fetch_invite_code_admin(&db_pool, &username)
            .await
            .ok_or_else(|| AppError::AuthError("User not found".to_string()))?;

        Ok(admin.into())
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct VerifyOTPSchema {
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct InviteCodeAdminData {
    pub username: String,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateInviteCodeSchema {
    #[serde(rename = "codeCount")]
    pub code_count: i32,
    #[serde(rename = "useCount")]
    pub use_count: i32,
}

/// Request for the single-code endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IssueInviteCodeSchema {
    /// How many accounts the code may create. Defaults to 1.
    #[serde(rename = "useCount", default = "default_use_count")]
    pub use_count: i32,
}

const fn default_use_count() -> i32 {
    1
}

/// The created code, returned so the caller can hand it to one applicant.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IssueInviteCodeResponse {
    pub code: String,
    #[serde(rename = "useCount")]
    pub use_count: i32,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateInviteCodeResponseSchema {
    pub account: String,
    pub codes: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct DisableInviteCodeSchema {
    pub codes: Vec<String>,
    pub accounts: Vec<String>,
}

/// A caller authenticated by Cloudflare Access.
///
/// Used by the machine-facing endpoints instead of the session cookie the
/// browser-facing ones rely on. Extraction fails closed: if Access is not
/// configured, no request is authenticated, rather than the endpoint quietly
/// accepting anything that can reach the origin.
#[derive(Debug, Clone)]
pub struct AccessClient(pub crate::access::AccessClaims);

impl<S> FromRequestParts<S> for AccessClient
where
    crate::config::Config: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = crate::config::Config::from_ref(state);

        let access = config.access.as_ref().ok_or_else(|| {
            AppError::AuthError(
                "Cloudflare Access is not configured on this deployment".to_string(),
            )
        })?;

        // Injected by Access itself and signed by the team's keys. The
        // Cf-Access-Client-Id header is not used: anything able to reach the
        // origin directly could set it.
        let token = parts
            .headers
            .get("cf-access-jwt-assertion")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::AuthError("Request did not arrive through Cloudflare Access".to_string())
            })?;

        Ok(Self(access.verify(token).await?))
    }
}
