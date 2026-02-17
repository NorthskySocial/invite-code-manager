use crate::DbConn;
use crate::db::create_invite_code_admin;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddAdminRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddAdminResponse {
    pub status: String,
    pub message: String,
    pub password: String,
}

fn validate_add_admin_request(body: &AddAdminRequest) -> Result<(), AppError> {
    if body.username.trim().is_empty() {
        return Err(AppError::BadRequest("Username cannot be empty".to_string()));
    }
    Ok(())
}

#[tracing::instrument(skip(db_pool, body, _user))]
#[utoipa::path(
    post,
    path = "/admins",
    request_body = AddAdminRequest,
    responses(
        (status = 201, description = "Admin user created successfully", body = AddAdminResponse),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn add_admin_handler(
    State(db_pool): State<DbConn>,
    _user: InviteCodeAdmin,
    Json(body): Json<AddAdminRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Adding new admin user: {}", body.username);

    // Validate input
    validate_add_admin_request(&body)?;

    // Generate a random password
    let password: String =
        rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 24);

    let username = body.username.clone();
    let password_clone = password.clone();
    match create_invite_code_admin(&db_pool, username.as_str(), password_clone.as_str()).await {
        Ok(_) => {
            let response = AddAdminResponse {
                status: "success".to_string(),
                message: format!("Admin user '{}' created successfully", body.username),
                password,
            };
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Err(AppError::InternalError(format!(
            "Admin user '{}' already exists",
            body.username
        ))),
        Err(e) => {
            tracing::error!("Database error creating admin: {}", e);
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use diesel::RunQueryDsl;
    use tower::ServiceExt;

    type TestDBPool = deadpool_diesel::sqlite::Pool;

    async fn setup_test_db(db_name: &str) -> TestDBPool {
        let manager = deadpool_diesel::sqlite::Manager::new(
            format!("file:{}?mode=memory&cache=shared", db_name),
            deadpool_diesel::Runtime::Tokio1,
        );
        let pool = deadpool_diesel::sqlite::Pool::builder(manager)
            .build()
            .expect("Failed to create test pool");

        let conn = pool.get().await.expect("Failed to get connection");
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
        })
        .await
        .expect("Interact error")
        .expect("Failed to create test table");

        pool
    }

    #[tokio::test]
    async fn test_add_admin_handler_unauthorized() {
        let pool = setup_test_db("add_admin_unauth").await;

        let app = Router::new()
            .route("/admins", post(add_admin_handler))
            .with_state(crate::DbConn(pool.clone()))
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let payload = AddAdminRequest {
            username: "newadmin".to_string(),
        };

        let req = Request::builder()
            .method("POST")
            .uri("/admins")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
