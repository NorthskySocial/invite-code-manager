use crate::LoginUser;
use crate::error::AppError;
use crate::helper::fetch_invite_code_admin_login;
use crate::routes::{DBPool, invite_code_admin_to_response};
use crate::user::InviteCodeAdminData;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};

#[tracing::instrument(skip(data, body, session))]
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
#[post("/auth/login")]
pub async fn login_user(
    data: Data<DBPool>,
    body: Json<LoginUser>,
    session: actix_session::Session,
) -> Result<HttpResponse, AppError> {
    tracing::info!("Login user");
    let mut conn = data
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
            session.renew();
            session
                .insert("username", body.username.clone())
                .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;

            if user.otp_verified == 1 {
                session
                    .insert("otp_enabled", "y")
                    .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;
                let response = invite_code_admin_to_response(&user);
                Ok(HttpResponse::Ok().json(response))
            } else {
                let response = invite_code_admin_to_response(&user);
                Ok(HttpResponse::Created().json(response))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoginUser;
    use crate::config::Config;
    use crate::helper::create_invite_code_admin;
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
    async fn test_login_user_success() {
        let pool = setup_test_db("login_success");
        let mut conn = pool.get().expect("Failed to get connection");

        // Create a user
        create_invite_code_admin(&mut conn, "testuser", "testpassword")
            .expect("Failed to create user");

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
                .service(login_user),
        )
        .await;

        let login_payload = LoginUser {
            username: "testuser".to_string(),
            password: "testpassword".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_login_user_invalid_credentials() {
        let pool = setup_test_db("login_invalid");
        let mut conn = pool.get().expect("Failed to get connection");

        // Create a user
        create_invite_code_admin(&mut conn, "testuser", "testpassword")
            .expect("Failed to create user");

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
                .service(login_user),
        )
        .await;

        let login_payload = LoginUser {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
