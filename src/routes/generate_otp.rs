use crate::error::AppError;
use crate::helper::{DBPool, update_otp};
use crate::user::InviteCodeAdmin;
use actix_web::web::Data;
use actix_web::{HttpResponse, post};
use rand::Rng;
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[tracing::instrument(skip(data, user))]
#[post("/auth/otp/generate")]
async fn generate_otp_handler(
    data: Data<DBPool>,
    user: InviteCodeAdmin,
) -> Result<HttpResponse, AppError> {
    let username = user.username;

    if user.otp_verified == 1 {
        return Err(AppError::InternalError("OTP already verified".to_string()));
    }

    let mut rng = rand::rng();
    let data_byte: [u8; 21] = rng.random();
    let base32_string = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(base32_string)
            .to_bytes()
            .map_err(|e| AppError::InternalError(e.to_string()))?,
    )
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    let otp_base32 = totp.get_secret_base32();
    let issuer = "InviteCodeManager";
    let otp_auth_url =
        format!("otpauth://totp/{issuer}:{username}?secret={otp_base32}&issuer={issuer}");

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    update_otp(
        &mut conn,
        username.as_str(),
        otp_base32.as_str(),
        otp_auth_url.as_str(),
    );

    Ok(HttpResponse::Ok().json(json!({"base32":otp_base32, "otpauth_url": otp_auth_url} )))
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
    async fn test_generate_otp_handler_unauthorized() {
        let db_name = "generate_otp_unauth";
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
                .service(generate_otp_handler),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/auth/otp/generate")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
