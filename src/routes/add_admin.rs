use crate::error::AppError;
use crate::helper::create_invite_code_admin;
use crate::routes::DBPool;
use crate::user::InviteCodeAdmin;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
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

#[tracing::instrument(skip(data, body, _user))]
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
#[post("/admins")]
pub async fn add_admin_handler(
    data: Data<DBPool>,
    body: Json<AddAdminRequest>,
    _user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
    tracing::info!("Adding new admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() {
        return Err(AppError::InternalError(
            "Username cannot be empty".to_string(),
        ));
    }

    // Generate a random password
    let password: String =
        rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 24);

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    match create_invite_code_admin(&mut conn, body.username.as_str(), password.as_str()) {
        Ok(_) => {
            let response = AddAdminResponse {
                status: "success".to_string(),
                message: format!("Admin user '{}' created successfully", body.username),
                password,
            };
            Ok(HttpResponse::Created().json(response))
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
    async fn test_add_admin_handler_unauthorized() {
        let pool = setup_test_db("add_admin_unauth");

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
                .service(add_admin_handler),
        )
        .await;

        let payload = AddAdminRequest {
            username: "newadmin".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/admins")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
