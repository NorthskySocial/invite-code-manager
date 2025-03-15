mod agent;
mod helper;
mod schema;
mod user;

use crate::helper::fetch_invite_code_admin;
use crate::user::{GenerateOTPSchema, InviteCodeAdmin, InviteCodeAdminData, VerifyOTPSchema};
use actix_web::dev::Server;
use actix_web::web::{Data, service};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, middleware, post, web};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::row::NamedRow;
use dotenvy::dotenv;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, io};
use totp_rs::{Algorithm, Secret, TOTP};
use web::Json;

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;

const GET_INVITE_CODES: &str = "/xrpc/com.atproto.admin.getInviteCodes";
const DISABLE_INVITE_CODES: &str = "/xrpc/com.atproto.admin.disableInviteCodes";
const CREATE_INVITE_CODE: &str = "/xrpc/com.atproto.admin.server.createInviteCode";
const CREATE_INVITE_CODES: &str = "/xrpc/com.atproto.admin.server.createInviteCodes";

#[derive(serde::Deserialize, Debug, serde::Serialize)]
pub struct LoginUser {
    username: String,
    password: String,
}

fn init_db(database_url: &str, db_min_idle: &str) -> Pool<ConnectionManager<SqliteConnection>> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    Pool::builder()
        .min_idle(Some(db_min_idle.parse().unwrap()))
        .build(manager)
        .expect("Failed to create pool")
}

fn init_http_server(
    pool: Pool<ConnectionManager<SqliteConnection>>,
    server_port: &str,
    worker_count: &str,
) -> Server {
    HttpServer::new(move || {
        let secret_key = actix_web::cookie::Key::from(&[0; 64]);
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(actix_session::SessionMiddleware::new(
                actix_session::storage::CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .app_data(Data::new(pool.clone()))
            .service(login_user)
            .service(generate_otp_handler)
            .service(verify_otp_handler)
            .service(validate_otp_handler)
    })
    .bind(format!("0.0.0.0:{}", server_port))
    .unwrap()
    .workers(worker_count.parse::<usize>().unwrap_or(2))
    .run()
}

#[post("/auth/login")]
async fn login_user(
    data: Data<DBPool>,
    body: Json<LoginUser>,
    session: actix_session::Session,
) -> HttpResponse {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    match user {
        None => {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: format!("No user with username: {} found", body.username),
            };

            return HttpResponse::NotFound().json(json_error)
        }
        Some(user) => {
            return HttpResponse::NotFound().json(())
        }
    }
}

#[post("/auth/otp/generate")]
async fn generate_otp_handler(body: Json<GenerateOTPSchema>, data: Data<DBPool>) -> impl Responder {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with username: {} found", body.username),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let mut rng = rand::thread_rng();
    let data_byte: [u8; 21] = rng.r#gen();
    let base32_string = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data_byte);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(base32_string).to_bytes().unwrap(),
    )
    .unwrap();

    let otp_base32 = totp.get_secret_base32();
    let username = body.username.to_owned();
    let issuer = "InviteCodeManager";
    let otp_auth_url =
        format!("otpauth://totp/{issuer}:{username}?secret={otp_base32}&issuer={issuer}");

    // let otp_auth_url = format!("otpauth://totp/<issuer>:<account_name>?secret=<secret>&issuer=<issuer>");
    let mut user = user.unwrap();
    user.otp_base32 = Some(otp_base32.to_owned());
    user.otp_auth_url = Some(otp_auth_url.to_owned());

    HttpResponse::Ok()
        .json(json!({"base32":otp_base32.to_owned(), "otpauth_url": otp_auth_url.to_owned()} ))
}

#[post("/auth/otp/verify")]
async fn verify_otp_handler(body: Json<VerifyOTPSchema>, data: Data<DBPool>) -> impl Responder {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with username: {} found", body.username),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let mut user = user.unwrap();

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Token is invalid or user doesn't exist".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    user.otp_enabled = 1;
    user.otp_verified = 1;

    HttpResponse::Ok()
        .json(json!({"otp_verified": true, "user": invite_code_admin_to_response(&user)}))
}

#[post("/auth/otp/validate")]
async fn validate_otp_handler(body: Json<VerifyOTPSchema>, data: Data<DBPool>) -> impl Responder {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with username: {} found", body.username),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();
    if !user.otp_enabled.eq(&1) {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}

#[post("/create-invite-codes")]
async fn create_invite_codes_handler(
    body: Json<VerifyOTPSchema>,
    data: Data<DBPool>,
) -> impl Responder {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with username: {} found", body.username),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();
    if !user.otp_enabled.eq(&1) {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}

#[get("/invite-codes")]
async fn get_invite_codes_handler(
    body: Json<VerifyOTPSchema>,
    data: Data<DBPool>,
) -> impl Responder {
    let user = fetch_invite_code_admin(&mut data.get().unwrap(), body.username.as_str());
    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with username: {} found", body.username),
        };

        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();
    if !user.otp_enabled.eq(&1) {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // Get Environment Variables
    let database_url = env::var("DATABASE_URL").unwrap_or("database".to_string());
    let db_min_idle = env::var("DB_MIN_IDLE").unwrap_or("1".to_string());
    let server_port = env::var("SERVER_PORT").unwrap_or("9090".to_string());
    let worker_count = env::var("WORKER_COUNT").unwrap_or("2".to_string());

    // Create DB Pool
    let db_pool = init_db(database_url.as_str(), db_min_idle.as_str());

    // Start Http Server
    let server = init_http_server(
        db_pool,
        server_port.as_str(),
        worker_count.as_str(),
    );
    server.await
}

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
