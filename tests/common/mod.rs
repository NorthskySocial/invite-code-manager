use axum::Router;
use axum::routing::{get, post};
use deadpool_diesel::sqlite::{Manager, Pool};
use diesel::RunQueryDsl;
use invite_code_manager::DBPooledConnection;
use invite_code_manager::apis::DBPool;
use invite_code_manager::apis::*;
use invite_code_manager::config::Config;
use invite_code_manager::user::InviteCodeAdmin;
use tower_sessions::{MemoryStore, SessionManagerLayer};

pub fn setup_test_db() -> DBPool {
    let manager = Manager::new(":memory:", deadpool_diesel::Runtime::Tokio1);
    let pool = Pool::builder(manager)
        .build()
        .expect("Failed to create test pool");

    invite_code_manager::DbConn(pool)
}

pub async fn init_db(pool: &DBPool) {
    let conn = pool.0.get().await.expect("Failed to get connection");
    conn.interact(|conn| {
        diesel::sql_query(
            "CREATE TABLE invite_code_admin (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otp_base32 TEXT,
                otp_auth_url TEXT,
                otp_enabled INTEGER NOT NULL DEFAULT 0,
                otp_verified INTEGER NOT NULL DEFAULT 0
            );",
        )
        .execute(conn)
        .expect("Failed to create test table");
    })
    .await
    .expect("Failed to interact with DB");
}

pub async fn setup_app(db_pool: DBPool) -> Router {
    let config = Config {
        pds_admin_password: "test_password".to_string(),
        pds_endpoint: "http://test-endpoint".to_string(),
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

    let app_state = AppState { db_pool, config };

    Router::new()
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
        .layer(session_layer)
        .with_state(app_state)
}

pub fn create_test_admin(conn: &mut DBPooledConnection, username: &str, password: &str) {
    let config = argon2::Config::default();
    let hashed_password =
        argon2::hash_encoded(password.as_bytes(), b"randomsalt", &config).unwrap();

    let new_user = InviteCodeAdmin {
        username: username.to_string(),
        password: hashed_password,
        otp_base32: None,
        otp_auth_url: None,
        otp_enabled: 0,
        otp_verified: 0,
    };

    diesel::insert_into(invite_code_manager::schema::invite_code_admin::table)
        .values(&new_user)
        .execute(conn)
        .expect("Failed to create test admin");
}
