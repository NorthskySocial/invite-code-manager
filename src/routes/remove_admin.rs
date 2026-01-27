use crate::error::AppError;
use crate::helper::delete_invite_code_admin;
use crate::routes::DBPool;
use crate::user::InviteCodeAdmin;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, delete};
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

#[tracing::instrument(skip(data, body, user))]
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
#[delete("/admins")]
pub async fn remove_admin_handler(
    data: Data<DBPool>,
    body: Json<RemoveAdminRequest>,
    user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
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

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    match delete_invite_code_admin(&mut conn, body.username.as_str()) {
        Ok(rows_affected) => {
            if rows_affected > 0 {
                let response = RemoveAdminResponse {
                    status: "success".to_string(),
                    message: format!("Admin user '{}' removed successfully", body.username),
                };
                Ok(HttpResponse::Ok().json(response))
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
    use crate::config::Config;
    use actix_session::SessionMiddleware;
    use actix_session::storage::CookieSessionStore;
    use actix_web::{App, cookie::Key, test};
    use diesel::RunQueryDsl;
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};

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

    #[actix_web::test]
    async fn test_remove_admin_handler_unauthorized() {
        let pool = setup_test_db("remove_admin_unauth");

        let secret_key = Key::generate();
        let config = Config {
            pds_admin_password: "pds_password".to_string(),
            pds_endpoint: "http://localhost".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool.clone()))
                .app_data(Data::new(config.clone()))
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    secret_key.clone(),
                ))
                .service(remove_admin_handler),
        )
        .await;

        let payload = RemoveAdminRequest {
            username: "admin_to_remove".to_string(),
        };

        let req = test::TestRequest::delete()
            .uri("/admins")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
