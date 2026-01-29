use crate::error::AppError;
use crate::helper::DBPool;
use crate::schema::invite_code_admin::username;
use actix_session::SessionExt;
use actix_web::dev::Payload;
use actix_web::web::Data;
use actix_web::{FromRequest, HttpRequest};
use diesel::{Insertable, QueryDsl, Queryable, RunQueryDsl, Selectable, SelectableHelper};
use serde::{Deserialize, Serialize};
use std::future::{Ready, ready};
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

impl FromRequest for InviteCodeAdmin {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let session = req.get_session();
        let username_session = match session.get::<String>("username") {
            Ok(Some(u)) => u,
            _ => return ready(Err(AppError::AuthError("Not logged in".to_string()))),
        };

        let db = match req.app_data::<Data<DBPool>>() {
            None => {
                return ready(Err(AppError::InternalError(
                    "Database pool not found".to_string(),
                )));
            }
            Some(conn) => conn.to_owned(),
        };

        use crate::schema::invite_code_admin::dsl::invite_code_admin;
        use diesel::ExpressionMethods;

        let mut conn = match db.get() {
            Ok(c) => c,
            Err(e) => return ready(Err(AppError::DatabaseError(e.to_string()))),
        };

        let results = invite_code_admin
            .filter(username.eq(username_session))
            .select(InviteCodeAdmin::as_select())
            .load(&mut conn);

        match results {
            Ok(admins) => {
                if let Some(admin) = admins.into_iter().next() {
                    if admin.otp_verified == 1 {
                        let otp_validated = session.get::<String>("otp_validated").unwrap_or(None);
                        if otp_validated.is_none() {
                            return ready(Err(AppError::AuthError("2FA required".to_string())));
                        }
                    }
                    ready(Ok(admin))
                } else {
                    ready(Err(AppError::NotFound("Admin user not found".to_string())))
                }
            }
            Err(e) => ready(Err(AppError::DatabaseError(e.to_string()))),
        }
    }
}

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
