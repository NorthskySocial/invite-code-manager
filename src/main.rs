extern crate argon2;

mod cli;
mod config;
mod error;
mod helper;
mod routes;
mod schema;
mod user;

use crate::config::Config;
use crate::routes::GenericResponse;
use crate::routes::create_invite_codes::create_invite_codes_handler;
use crate::routes::disable_invite_codes::disable_invite_codes_handler;
use crate::routes::generate_otp::generate_otp_handler;
use crate::routes::get_invite_codes::get_invite_codes_handler;
use crate::routes::health::healthcheck_handler;
use crate::routes::login::login_user;
use crate::routes::validate_otp::validate_otp_handler;
use crate::routes::verify_otp::verify_otp_handler;
use actix_cors::Cors;
use actix_web::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use actix_web::web::Data;
use actix_web::{App, HttpServer, middleware};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use dotenvy::dotenv;
use std::{env, io};

const GET_INVITE_CODES: &str = "/xrpc/com.atproto.admin.getInviteCodes";
const DISABLE_INVITE_CODES: &str = "/xrpc/com.atproto.admin.disableInviteCodes";
const CREATE_INVITE_CODES: &str = "/xrpc/com.atproto.server.createInviteCodes";

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

fn create_cors() -> Cors {
    Cors::default()
        .allow_any_origin()
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![CONTENT_TYPE, ACCESS_CONTROL_ALLOW_ORIGIN])
        .supports_credentials()
        .max_age(3600)
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // Get Environment Variables
    let pds_admin_password =
        env::var("PDS_ADMIN_PASSWORD").expect("env variable PDS_ADMIN_PASSWORD should be set");
    let pds_endpoint = env::var("PDS_ENDPOINT").expect("env variable PDS_ENDPOINT should be set");
    let database_url = env::var("DATABASE_URL").expect("env variable DATABASE_URL should be set");
    let db_min_idle = env::var("DB_MIN_IDLE").unwrap_or("1".to_string());
    let server_port = env::var("SERVER_PORT").unwrap_or("9090".to_string());
    let worker_count: usize = env::var("WORKER_COUNT")
        .unwrap_or("2".to_string())
        .parse()
        .unwrap();

    // Create DB Pool
    let db_pool = init_db(database_url.as_str(), db_min_idle.as_str());

    // Check for CLI commands (if none are provided, start the server instead)
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "create-user" => {
                let mut conn = db_pool.get().expect("Failed to get DB connection");
                if let Err(e) = cli::create_user(&mut conn) {
                    tracing::error!("Error creating user: {}", e);
                }
                return Ok(());
            }
            "list-users" => {
                let mut conn = db_pool.get().expect("Failed to get DB connection");
                if let Err(e) = cli::list_users(&mut conn) {
                    tracing::error!("Error listing users: {}", e);
                }
                return Ok(());
            }
            _ => {
                tracing::info!("Unknown command: {}", args[1]);
                return Ok(());
            }
        }
    }

    // Setup Config
    let config = Config {
        pds_admin_password,
        pds_endpoint,
    };

    // Start Http Server
    tracing::info!(
        "[Invite Code Manager] Starting server on port {}",
        server_port
    );
    HttpServer::new(move || {
        let secret_key = actix_web::cookie::Key::from(&[0; 64]);
        let cors = create_cors();
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .wrap(actix_session::SessionMiddleware::new(
                actix_session::storage::CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .app_data(Data::new(db_pool.clone()))
            .app_data(Data::new(config.clone()))
            .service(healthcheck_handler)
            .service(login_user)
            .service(generate_otp_handler)
            .service(verify_otp_handler)
            .service(validate_otp_handler)
            .service(create_invite_codes_handler)
            .service(get_invite_codes_handler)
            .service(disable_invite_codes_handler)
    })
    .bind(format!("0.0.0.0:{}", server_port))?
    .workers(worker_count)
    .run()
    .await
}
