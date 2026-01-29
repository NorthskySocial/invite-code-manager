extern crate argon2;

use actix_cors::Cors;
use actix_web::cookie::Key;
use actix_web::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use actix_web::web::Data;
use actix_web::{App, HttpServer, middleware};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use dotenvy::dotenv;
use invite_code_manager::cli;
use invite_code_manager::config::Config;
use invite_code_manager::routes::add_admin::add_admin_handler;
use invite_code_manager::routes::create_invite_codes::create_invite_codes_handler;
use invite_code_manager::routes::disable_invite_codes::disable_invite_codes_handler;
use invite_code_manager::routes::generate_otp::generate_otp_handler;
use invite_code_manager::routes::get_invite_codes::get_invite_codes_handler;
use invite_code_manager::routes::health::healthcheck_handler;
use invite_code_manager::routes::list_admins::list_admins_handler;
use invite_code_manager::routes::login::login_user;
use invite_code_manager::routes::remove_admin::remove_admin_handler;
use invite_code_manager::routes::validate_otp::validate_otp_handler;
use invite_code_manager::routes::verify_otp::verify_otp_handler;
use std::{env, io};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        invite_code_manager::routes::health::healthcheck_handler,
        invite_code_manager::routes::login::login_user,
        invite_code_manager::routes::generate_otp::generate_otp_handler,
        invite_code_manager::routes::verify_otp::verify_otp_handler,
        invite_code_manager::routes::validate_otp::validate_otp_handler,
        invite_code_manager::routes::create_invite_codes::create_invite_codes_handler,
        invite_code_manager::routes::get_invite_codes::get_invite_codes_handler,
        invite_code_manager::routes::disable_invite_codes::disable_invite_codes_handler,
        invite_code_manager::routes::add_admin::add_admin_handler,
        invite_code_manager::routes::remove_admin::remove_admin_handler,
        invite_code_manager::routes::list_admins::list_admins_handler,
    ),
    components(
        schemas(
            invite_code_manager::LoginUser,
            invite_code_manager::user::InviteCodeAdminData,
            invite_code_manager::user::VerifyOTPSchema,
            invite_code_manager::user::CreateInviteCodeSchema,
            invite_code_manager::user::DisableInviteCodeSchema,
            invite_code_manager::routes::add_admin::AddAdminRequest,
            invite_code_manager::routes::add_admin::AddAdminResponse,
            invite_code_manager::routes::remove_admin::RemoveAdminRequest,
            invite_code_manager::routes::remove_admin::RemoveAdminResponse,
            invite_code_manager::routes::list_admins::ListAdminsResponse,
            invite_code_manager::routes::generate_otp::GenerateOTPResponse,
            invite_code_manager::routes::verify_otp::VerifyOTPResponse,
            invite_code_manager::routes::validate_otp::ValidateOTPResponse,
            invite_code_manager::routes::Code,
            invite_code_manager::routes::Use,
            invite_code_manager::routes::InviteCodes,
        )
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "session_cookie",
            utoipa::openapi::security::SecurityScheme::ApiKey(
                utoipa::openapi::security::ApiKey::Cookie(
                    utoipa::openapi::security::ApiKeyValue::new("invite_manager_session"),
                ),
            ),
        )
    }
}

fn init_db(database_url: &str, db_min_idle: &str) -> Pool<ConnectionManager<SqliteConnection>> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    Pool::builder()
        .min_idle(Some(db_min_idle.parse().unwrap()))
        .build(manager)
        .expect("Failed to create pool")
}

fn create_cors() -> Cors {
    let allowed_origin = env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| "*".to_string());

    let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            CONTENT_TYPE,
            actix_web::http::header::AUTHORIZATION,
            actix_web::http::header::ACCEPT,
            ACCESS_CONTROL_ALLOW_ORIGIN,
            actix_web::http::header::X_CONTENT_TYPE_OPTIONS,
        ])
        .supports_credentials()
        .max_age(3600);

    if allowed_origin == "*" {
        cors.allow_any_origin()
    } else {
        cors.allowed_origin(&allowed_origin)
    }
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
        return match args[1].as_str() {
            "create-user" => {
                let mut conn = db_pool.get().expect("Failed to get DB connection");
                if let Err(e) = cli::create_user(&mut conn) {
                    tracing::error!("Error creating user: {}", e);
                }
                Ok(())
            }
            "list-users" => {
                let mut conn = db_pool.get().expect("Failed to get DB connection");
                if let Err(e) = cli::list_users(&mut conn) {
                    tracing::error!("Error listing users: {}", e);
                }
                Ok(())
            }
            _ => {
                tracing::info!("Unknown command: {}", args[1]);
                Ok(())
            }
        };
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

    let session_key = env::var("SESSION_KEY")
        .map(|s| Key::from(s.as_bytes()))
        .unwrap_or_else(|_| Key::from(&[0; 64]));

    HttpServer::new(move || {
        let cors = create_cors();
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .wrap(
                actix_session::SessionMiddleware::builder(
                    actix_session::storage::CookieSessionStore::default(),
                    session_key.clone(),
                )
                .cookie_http_only(true)
                .cookie_secure(true)
                .cookie_same_site(actix_web::cookie::SameSite::Strict)
                .cookie_name("invite_manager_session".to_string())
                .session_lifecycle(actix_session::config::SessionLifecycle::BrowserSession(
                    actix_session::config::BrowserSession::default(),
                ))
                .build(),
            )
            .app_data(Data::new(db_pool.clone()))
            .app_data(Data::new(config.clone()))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(healthcheck_handler)
            .service(login_user)
            .service(generate_otp_handler)
            .service(verify_otp_handler)
            .service(validate_otp_handler)
            .service(create_invite_codes_handler)
            .service(get_invite_codes_handler)
            .service(disable_invite_codes_handler)
            .service(add_admin_handler)
            .service(remove_admin_handler)
            .service(list_admins_handler)
    })
    .bind(format!("0.0.0.0:{}", server_port))?
    .workers(worker_count)
    .run()
    .await
}
