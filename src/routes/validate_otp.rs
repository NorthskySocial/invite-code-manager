use crate::error::AppError;
use crate::user::{InviteCodeAdmin, VerifyOTPSchema};
use actix_web::web::Json;
use actix_web::{HttpResponse, post};
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[tracing::instrument(skip(body, invite_code_admin, session), fields(user_id = %invite_code_admin.username
))]
#[post("/auth/otp/validate")]
async fn validate_otp_handler(
    body: Json<VerifyOTPSchema>,
    invite_code_admin: InviteCodeAdmin,
    session: actix_session::Session,
) -> Result<HttpResponse, AppError> {
    if !invite_code_admin.otp_enabled.eq(&1) {
        return Err(AppError::AuthError("2FA not enabled".to_string()));
    }

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

    session
        .insert("otp_validated", invite_code_admin.username.clone())
        .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;

    Ok(HttpResponse::Ok().json(json!({"otp_valid": true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::helper::create_invite_code_admin;
    use actix_session::SessionMiddleware;
    use actix_session::storage::CookieSessionStore;
    use actix_web::{App, cookie::Key, test, web::Data};
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{ExpressionMethods, RunQueryDsl};

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
    async fn test_validate_otp_handler_success() {
        let db_name = "validate_otp_success";
        let pool = setup_test_db(db_name);
        let mut conn = pool.get().expect("Failed to get connection");

        let username = "testuser";
        create_invite_code_admin(&mut conn, username, "testpassword")
            .expect("Failed to create user");

        // Manually enable OTP for the user - Use 20 bytes (160 bits) secret which is common
        // "MFRGGZDFMZTWQ2LK" is 16 chars base32 -> 10 bytes -> 80 bits.
        // Let's use 32 chars -> 20 bytes -> 160 bits.
        let base32_secret = "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK";
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_secret.to_string())
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let otp_base32 = totp.get_secret_base32();

        diesel::update(crate::schema::invite_code_admin::table)
            .filter(crate::schema::invite_code_admin::username.eq(username))
            .set((
                crate::schema::invite_code_admin::otp_enabled.eq(1),
                crate::schema::invite_code_admin::otp_base32.eq(otp_base32.clone()),
            ))
            .execute(&mut conn)
            .unwrap();

        let token = totp.generate_current().unwrap();

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
                .service(validate_otp_handler),
        )
        .await;

        let payload = VerifyOTPSchema { token };

        let req = test::TestRequest::post()
            .uri("/auth/otp/validate")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Without session, FromRequest for InviteCodeAdmin fails -> 401 Unauthorized
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_validate_otp_handler_invalid_token() {
        let db_name = "validate_otp_invalid";
        let pool = setup_test_db(db_name);
        let mut conn = pool.get().expect("Failed to get connection");

        let username = "testuser";
        create_invite_code_admin(&mut conn, username, "testpassword")
            .expect("Failed to create user");

        let base32_secret = "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK";
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_secret.to_string())
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let otp_base32 = totp.get_secret_base32();

        diesel::update(crate::schema::invite_code_admin::table)
            .filter(crate::schema::invite_code_admin::username.eq(username))
            .set((
                crate::schema::invite_code_admin::otp_enabled.eq(1),
                crate::schema::invite_code_admin::otp_base32.eq(otp_base32),
            ))
            .execute(&mut conn)
            .unwrap();

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
                .service(validate_otp_handler),
        )
        .await;

        let payload = VerifyOTPSchema {
            token: "000000".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/auth/otp/validate")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
