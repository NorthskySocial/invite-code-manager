use crate::error::AuthError;
use crate::helper::{DBPooledConnection, fetch_invite_code_admin_by_session};
use actix_web::dev::Payload;
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized, HttpError};
use actix_web::http::header::{HeaderValue, ToStrError};
use actix_web::{FromRequest, HttpMessage, HttpRequest, http};
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use std::future::{Ready, ready};

#[derive(Queryable, Selectable, Clone, Debug, Deserialize, Serialize, Insertable)]
#[diesel(table_name = crate::schema::invite_code_admin)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct InviteCodeAdmin {
    pub username: String,
    pub password: String,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
    pub otp_enabled: i32,
    pub otp_verified: i32,
}

#[derive(Debug, Deserialize)]
pub struct UserRegisterSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UserLoginSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOTPSchema {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateOTPSchema {
    pub token: String,
}

#[derive(Serialize, Debug)]
pub struct InviteCodeAdminData {
    pub username: String,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
}

impl FromRequest for InviteCodeAdmin {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let auth_header = match req.headers().get("Authorization") {
            None => {
                return ready(Err(ErrorUnauthorized(AuthError {
                    status: "".to_string(),
                    message: "".to_string(),
                })));
            }
            Some(auth_header) => match auth_header.to_str() {
                Ok(auth_header) => auth_header.to_owned(),
                Err(e) => {
                    println!("{}", e);
                    return ready(Err(ErrorUnauthorized(AuthError {
                        status: "".to_string(),
                        message: "".to_string(),
                    })));
                }
            },
        };
        let db = match req.app_data::<DBPooledConnection>() {
            None => {
                return ready(Err(ErrorInternalServerError(AuthError {
                    status: "".to_string(),
                    message: "".to_string(),
                })));
            }
            Some(conn) => conn.to_owned(),
        };
        let invite_code_admin = Ok(fetch_invite_code_admin_by_session(db, auth_header.as_str()));
        ready(invite_code_admin)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateInviteCodeSchema {
    #[serde(rename = "codeCount")]
    pub code_count: i32,
    #[serde(rename = "useCount")]
    pub use_count: i32,
}

#[derive(Serialize, Deserialize)]
pub struct CreateInviteCodeResponseSchema {
    pub account: String,
    pub codes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DisableInviteCodeSchema {
    pub codes: Vec<String>,
    pub accounts: Vec<String>,
}

#[derive(Queryable, Selectable, Clone, Debug, Deserialize, Serialize, Insertable)]
#[diesel(table_name = crate::schema::user_session)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct UserSession {
    pub username: String,
    pub otp_verified: i32,
    pub active: i32,
}