use crate::error::AuthError;
use crate::helper::DBPool;
use crate::schema::invite_code_admin::username;
use actix_session::SessionExt;
use actix_web::dev::Payload;
use actix_web::error::ErrorInternalServerError;
use actix_web::web::Data;
use actix_web::{FromRequest, HttpRequest};
use diesel::{Insertable, QueryDsl, Queryable, RunQueryDsl, Selectable, SelectableHelper};
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
pub struct VerifyOTPSchema {
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
        let i = req.get_session().get::<String>("username").unwrap();
        let _username = i.unwrap();
        let db = match req.app_data::<Data<DBPool>>() {
            None => {
                return ready(Err(ErrorInternalServerError(AuthError {
                    status: "".to_string(),
                    message: "".to_string(),
                })));
            }
            Some(conn) => conn.to_owned(),
        };

        use crate::schema::invite_code_admin::dsl::invite_code_admin;
        use diesel::ExpressionMethods;
        let results = invite_code_admin
            .filter(username.eq(_username))
            .select(InviteCodeAdmin::as_select())
            .load(&mut db.get().unwrap())
            .expect("DB Exception");
        ready(Ok(results.first().unwrap().clone()))
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
