use crate::DbConn;
use crate::apis::invite_code_admin_to_response;
use crate::error::AppError;
use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use axum::extract::State;
use axum::{Json, response::IntoResponse};
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ListAdminsResponse {
    pub status: String,
    pub admins: Vec<InviteCodeAdminData>,
}

#[tracing::instrument(skip(db_pool, _user))]
#[utoipa::path(
    get,
    path = "/admins",
    responses(
        (status = 200, description = "List of admin users retrieved successfully", body = ListAdminsResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn list_admins_handler(
    _user: InviteCodeAdmin,
    State(db_pool): State<DbConn>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Listing all admin users");

    let conn = db_pool
        .0
        .get()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    use crate::schema::invite_code_admin::dsl::invite_code_admin;

    let results = conn
        .interact(move |conn| {
            invite_code_admin
                .select(InviteCodeAdmin::as_select())
                .load::<InviteCodeAdmin>(conn)
        })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let admins_data: Vec<InviteCodeAdminData> =
        results.iter().map(invite_code_admin_to_response).collect();

    let response = ListAdminsResponse {
        status: "success".to_string(),
        admins: admins_data,
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
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
    async fn test_list_admins_handler_unauthorized() {
        let pool = setup_test_db("list_admins_unauth").await;

        let app = Router::new()
            .route("/admins", get(list_admins_handler))
            .with_state(crate::DbConn(pool.clone()))
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let req = Request::builder()
            .method("GET")
            .uri("/admins")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
