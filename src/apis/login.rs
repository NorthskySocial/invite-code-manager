use crate::LoginUser;
use crate::apis::{DBPool, invite_code_admin_to_response};
use crate::db::fetch_invite_code_admin_login;
use crate::error::AppError;
use crate::user::InviteCodeAdminData;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use tower_sessions::Session;

#[tracing::instrument(skip(db_pool, body, session))]
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginUser,
    responses(
        (status = 200, description = "Login successful", body = InviteCodeAdminData),
        (status = 201, description = "Login successful, OTP setup required", body = InviteCodeAdminData),
        (status = 401, description = "Invalid credentials")
    )
)]
pub async fn login_user(
    State(db_pool): State<DBPool>,
    session: Session,
    Json(body): Json<LoginUser>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Login user");
    let mut conn = db_pool
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    let user =
        fetch_invite_code_admin_login(&mut conn, body.username.as_str(), body.password.as_str());
    match user {
        None => Err(AppError::AuthError(format!(
            "Invalid username or password for: {}",
            body.username
        ))),
        Some(user) => {
            session
                .insert("username", body.username.clone())
                .await
                .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;

            if user.otp_verified == 1 {
                let response = invite_code_admin_to_response(&user);
                Ok((StatusCode::OK, Json(response)).into_response())
            } else {
                session
                    .insert("2fa_not_required", "y")
                    .await
                    .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;
                let response = invite_code_admin_to_response(&user);
                Ok((StatusCode::CREATED, Json(response)).into_response())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoginUser;
    use crate::helper::create_invite_code_admin;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use diesel::RunQueryDsl;
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};
    use tower::ServiceExt;
    use tower_sessions::{MemoryStore, SessionManagerLayer};

    type TestDBPool = Pool<ConnectionManager<SqliteConnection>>;

    fn setup_test_db(db_name: &str) -> TestDBPool {
        let manager = ConnectionManager::<SqliteConnection>::new(format!(
            "file:{}?mode=memory&cache=shared",
            db_name
        ));
        let pool = Pool::builder()
            .build(manager)
            .expect("Failed to create test pool");

        let mut conn = pool.get().expect("Failed to get connection");
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
        .execute(&mut conn)
        .expect("Failed to create test table");

        pool
    }

    #[tokio::test]
    async fn test_login_user_success() {
        let pool = setup_test_db("login_success");
        let mut conn = pool.get().expect("Failed to get connection");

        // Create a user
        create_invite_code_admin(&mut conn, "testuser", "testpassword")
            .expect("Failed to create user");

        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store);

        let app = Router::new()
            .route("/auth/login", post(login_user))
            .layer(session_layer)
            .with_state(pool.clone());

        let login_payload = LoginUser {
            username: "testuser".to_string(),
            password: "testpassword".to_string(),
        };

        let req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn test_login_user_invalid_credentials() {
        let pool = setup_test_db("login_invalid");
        let mut conn = pool.get().expect("Failed to get connection");

        // Create a user
        create_invite_code_admin(&mut conn, "testuser", "testpassword")
            .expect("Failed to create user");

        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store);

        let app = Router::new()
            .route("/auth/login", post(login_user))
            .layer(session_layer)
            .with_state(pool.clone());

        let login_payload = LoginUser {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        };

        let req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
