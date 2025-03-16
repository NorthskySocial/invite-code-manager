use crate::GET_INVITE_CODES;
use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use actix_web::HttpResponse;
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use serde::{Deserialize, Serialize};

pub mod create_invite_codes;
pub mod disable_invite_codes;
pub mod generate_otp;
pub mod get_invite_codes;
pub mod login;
pub mod validate_otp;
pub mod verify_otp;

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Use {
    #[serde(rename = "usedBy")]
    pub used_by: String,
    #[serde(rename = "usedAt")]
    pub used_at: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Code {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    #[serde(rename = "forAccount")]
    pub for_account: String,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub uses: Vec<Use>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct InviteCodes {
    pub cursor: String,
    pub codes: Vec<Code>,
}

async fn get_invite_codes() -> Result<Vec<Code>, ()> {
    let mut codes: Vec<Code> = vec![];
    let client = reqwest::Client::new();
    let res = client
        .get("https://pds.ripperoni.com".to_string() + GET_INVITE_CODES)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some("password"))
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        panic!("not success")
    }
    let invite_codes = res.json::<InviteCodes>().await;
    match invite_codes {
        Ok(invite_codes) => {
            codes.append(&mut invite_codes.codes.clone());
        }
        Err(e) => {
            eprintln!("{}", e);
            panic!("Invite Codes")
        }
    }
    Ok(codes)
}

#[derive(Serialize)]
pub struct GenericResponse {
    pub status: String,
    pub message: String,
}

fn invite_code_admin_to_response(user: &InviteCodeAdmin) -> InviteCodeAdminData {
    InviteCodeAdminData {
        username: user.username.to_owned(),
        otp_auth_url: user.otp_auth_url.to_owned(),
        otp_base32: user.otp_base32.to_owned(),
        otp_enabled: user.otp_enabled.eq(&1),
        otp_verified: user.otp_verified.eq(&1),
    }
}

// #[post("/logout/")]
// pub async fn log_out(session: actix_session::Session) -> HttpResponse {
//     match session_user_id(&session).await {
//         Ok(_) => {
//             tracing::event!(target: "backend", tracing::Level::INFO, "Users retrieved from the DB.");
//             session.purge();
//             actix_web::HttpResponse::Ok().json(crate::types::SuccessResponse {
//                 message: "You have successfully logged out".to_string(),
//             })
//         }
//         Err(e) => {
//             tracing::event!(target: "backend",tracing::Level::ERROR, "Failed to get user from session: {:#?}", e);
//             HttpResponse::BadRequest().json(crate::types::ErrorResponse {
//                 error:
//                     "We currently have some issues. Kindly try again and ensure you are logged in"
//                         .to_string(),
//             })
//         }
//     }
// }

// async fn session_user_id(session: &actix_session::Session) -> Result<String, String> {
//     match session.get(crate::types::USER_ID_KEY) {
//         Ok(user_id) => match user_id {
//             None => Err("You are not authenticated".to_string()),
//             Some(id) => Ok(id),
//         },
//         Err(e) => Err(format!("{e}")),
//     }
// }

fn get_user_id(session: actix_session::Session) -> Result<String, HttpResponse> {
    return match session.get("username") {
        Ok(user_id_key) => match user_id_key {
            None => Err(HttpResponse::Unauthorized().finish()),
            Some(id) => Ok(id),
        },
        Err(_e) => Err(HttpResponse::InternalServerError().finish()),
    };
}
