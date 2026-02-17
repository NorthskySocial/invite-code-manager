extern crate argon2;

use axum::{
    Router,
    routing::{get, post},
};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use dotenvy::dotenv;
use invite_code_manager::apis::{
    add_admin_handler, create_invite_codes_handler, disable_invite_codes_handler,
    generate_otp_handler, get_invite_codes_handler, healthcheck_handler, list_admins_handler,
    login_user, remove_admin_handler, validate_otp_handler, verify_otp_handler,
};
use invite_code_manager::cli;
use invite_code_manager::config::Config;
use invite_code_manager::db::DBPool;
use std::{env, io};
use tower_http::cors::{Any, CorsLayer};
use tower_sessions::{MemoryStore, SessionManagerLayer};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        invite_code_manager::apis::health::healthcheck_handler,
        invite_code_manager::apis::login::login_user,
        invite_code_manager::apis::add_admin::add_admin_handler,
        invite_code_manager::apis::list_admins::list_admins_handler,
        invite_code_manager::apis::remove_admin::remove_admin_handler,
        invite_code_manager::apis::generate_otp::generate_otp_handler,
        invite_code_manager::apis::verify_otp::verify_otp_handler,
        invite_code_manager::apis::validate_otp::validate_otp_handler,
        invite_code_manager::apis::create_invite_codes::create_invite_codes_handler,
        invite_code_manager::apis::get_invite_codes::get_invite_codes_handler,
        invite_code_manager::apis::disable_invite_codes::disable_invite_codes_handler,
    ),
    components(
        schemas(
            invite_code_manager::LoginUser,
            invite_code_manager::user::InviteCodeAdminData,
            invite_code_manager::user::VerifyOTPSchema,
            invite_code_manager::user::CreateInviteCodeSchema,
            invite_code_manager::user::DisableInviteCodeSchema,
            invite_code_manager::apis::Code,
            invite_code_manager::apis::Use,
            invite_code_manager::apis::InviteCodes,
            invite_code_manager::apis::add_admin::AddAdminRequest,
            invite_code_manager::apis::add_admin::AddAdminResponse,
            invite_code_manager::apis::list_admins::ListAdminsResponse,
            invite_code_manager::apis::remove_admin::RemoveAdminRequest,
            invite_code_manager::apis::remove_admin::RemoveAdminResponse,
            invite_code_manager::apis::generate_otp::GenerateOTPResponse,
            invite_code_manager::apis::verify_otp::VerifyOTPResponse,
            invite_code_manager::apis::validate_otp::ValidateOTPResponse,
        )
    ),
    modifiers(&SecurityAddon)
)]
#[allow(dead_code)]
struct ApiDoc;

#[allow(dead_code)]
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

#[tokio::main]
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

    let db_manager =
        deadpool_diesel::sqlite::Manager::new(database_url, deadpool_diesel::Runtime::Tokio1);

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

    let allowed_origin = env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let cors = if allowed_origin == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origin: axum::http::HeaderValue = allowed_origin.parse().unwrap();
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    #[derive(Clone)]
    struct AppState {
        db_pool: DBPool,
        config: Config,
    }

    impl axum::extract::FromRef<AppState> for DBPool {
        fn from_ref(state: &AppState) -> DBPool {
            state.db_pool.clone()
        }
    }

    impl axum::extract::FromRef<AppState> for Config {
        fn from_ref(state: &AppState) -> Config {
            state.config.clone()
        }
    }

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    let app_state = AppState {
        db_pool: db_manager,
        config: config.clone(),
    };

    let app = Router::new()
        .route("/health", get(healthcheck_handler))
        .route("/auth/login", post(login_user))
        .route(
            "/admins",
            get(list_admins_handler)
                .post(add_admin_handler)
                .delete(remove_admin_handler),
        )
        .route("/auth/otp/generate", post(generate_otp_handler))
        .route("/auth/otp/verify", post(verify_otp_handler))
        .route("/auth/otp/validate", post(validate_otp_handler))
        .route("/create-invite-codes", post(create_invite_codes_handler))
        .route("/invite-codes", get(get_invite_codes_handler))
        .route("/disable-invite-codes", post(disable_invite_codes_handler))
        .with_state(app_state);

    let app = app.layer(session_layer).layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", server_port))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("server error");

    Ok(())
}
