use crate::db::fetch_invite_code_admin;
use crate::{DbConn, error::AppError};
use axum::async_trait;
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

#[async_trait]
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

            if otp_validated.is_none() {
                return Err(AppError::AuthError("2FA required".to_string()));
            }
        }

        Ok(admin)
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

// TODO: Re-implement Axum extractor for InviteCodeAdmin after all routes are migrated.

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateInviteCodeSchema {
    #[serde(rename = "codeCount")]
    pub code_count: i32,
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
