use crate::apis::DBPool;
use crate::db::delete_invite_code_admin;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemoveAdminRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemoveAdminResponse {
    pub status: String,
    pub message: String,
}

#[tracing::instrument(skip(db_pool, body, user))]
#[utoipa::path(
    delete,
    path = "/admins",
    request_body = RemoveAdminRequest,
    responses(
        (status = 200, description = "Admin user removed successfully", body = RemoveAdminResponse),
        (status = 401, description = "Unauthorized or cannot delete self"),
        (status = 404, description = "Admin user not found")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn remove_admin_handler(
    State(db_pool): State<DBPool>,
    user: InviteCodeAdmin, // Requires authentication
    Json(body): Json<RemoveAdminRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Removing admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() {
        return Err(AppError::InternalError(
            "Username cannot be empty".to_string(),
        ));
    }

    // Prevent self-deletion
    if user.username == body.username {
        return Err(AppError::AuthError(
            "Cannot delete your own admin account".to_string(),
        ));
    }

    let mut conn = db_pool
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    match delete_invite_code_admin(&mut conn, body.username.as_str()) {
        Ok(rows_affected) => {
            if rows_affected > 0 {
                let response = RemoveAdminResponse {
                    status: "success".to_string(),
                    message: format!("Admin user '{}' removed successfully", body.username),
                };
                Ok(Json(response))
            } else {
                Err(AppError::NotFound(format!(
                    "Admin user '{}' not found",
                    body.username
                )))
            }
        }
        Err(e) => {
            tracing::error!("Database error removing admin: {}", e);
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
        routing::delete,
    };
    use diesel::RunQueryDsl;
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};
    use tower::ServiceExt;

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
    async fn test_remove_admin_handler_unauthorized() {
        let pool = setup_test_db("remove_admin_unauth");

        let app = Router::new()
            .route("/admins", delete(remove_admin_handler))
            .with_state(pool.clone())
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let payload = RemoveAdminRequest {
            username: "admin_to_remove".to_string(),
        };

        let req = Request::builder()
            .method("DELETE")
            .uri("/admins")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
