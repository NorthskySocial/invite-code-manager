use crate::error::AppError;
use crate::helper::{DBPool, verify_otp};
use crate::routes::invite_code_admin_to_response;
use crate::user::{InviteCodeAdmin, VerifyOTPSchema};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[tracing::instrument(skip(data, invite_code_admin, session), fields(user_id = %invite_code_admin.username.clone()
))]
#[post("/auth/otp/verify")]
async fn verify_otp_handler(
    body: Json<VerifyOTPSchema>,
    data: Data<DBPool>,
    invite_code_admin: InviteCodeAdmin,
    session: actix_session::Session,
) -> Result<HttpResponse, AppError> {
    let otp_base32 = invite_code_admin
        .otp_base32
        .clone()
        .ok_or_else(|| AppError::InternalError("OTP not generated for this user".to_string()))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32)
            .to_bytes()
            .map_err(|e| AppError::InternalError(e.to_string()))?,
    )
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    let is_valid = totp
        .check_current(&body.token)
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    if !is_valid {
        return Err(AppError::AuthError("Token is invalid".to_string()));
    }

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    verify_otp(&mut conn, invite_code_admin.username.as_str());

    session
        .insert("otp_validated", invite_code_admin.username.clone())
        .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;

    Ok(HttpResponse::Ok().json(
        json!({"otp_verified": true, "user": invite_code_admin_to_response(&invite_code_admin)}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use actix_session::SessionMiddleware;
    use actix_session::storage::CookieSessionStore;
    use actix_web::{App, cookie::Key, test, web::Data};
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
    async fn test_verify_otp_handler_unauthorized() {
        let db_name = "verify_otp_unauth";
        let pool = setup_test_db(db_name);

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
                .service(verify_otp_handler),
        )
        .await;

        let payload = VerifyOTPSchema {
            token: "123456".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/auth/otp/verify")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
