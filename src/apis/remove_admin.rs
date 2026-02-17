use crate::DbConn;
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
    State(db_pool): State<DbConn>,
    user: InviteCodeAdmin,
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

    let username_to_delete = body.username.clone();
    match delete_invite_code_admin(&db_pool, username_to_delete.as_str()).await {
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
    async fn test_remove_admin_handler_unauthorized() {
        let pool = setup_test_db("remove_admin_unauth").await;

        let app = Router::new()
            .route("/admins", delete(remove_admin_handler))
            .with_state(crate::DbConn(pool.clone()))
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
