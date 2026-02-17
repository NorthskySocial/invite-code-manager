use crate::DbConn;
use crate::db::update_otp;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::extract::State;
use axum::{Json, response::IntoResponse};
use rand::Rng;
use serde::Serialize;
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct GenerateOTPResponse {
    pub base32: String,
    pub otpauth_url: String,
}

#[tracing::instrument(skip(db_pool, user))]
#[utoipa::path(
    post,
    path = "/auth/otp/generate",
    responses(
        (status = 200, description = "OTP generated successfully", body = GenerateOTPResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn generate_otp_handler(
    State(db_pool): State<DbConn>,
    user: InviteCodeAdmin,
) -> Result<impl IntoResponse, AppError> {
    let username = user.username;

    if user.otp_verified == 1 {
        return Err(AppError::InternalError("OTP already verified".to_string()));
    }

    let base32_string = {
        let mut rng = rand::rng();
        let data_byte: [u8; 21] = rng.random();
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte)
    };

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

    update_otp(
        &db_pool,
        username.as_str(),
        otp_base32.as_str(),
        otp_auth_url.as_str(),
    )
    .await;

    Ok(Json(GenerateOTPResponse {
        base32: otp_base32,
        otpauth_url: otp_auth_url,
    }))
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
    async fn test_generate_otp_handler_unauthorized() {
        let pool = setup_test_db("generate_otp_unauth").await;

        let app = Router::new()
            .route("/auth/otp/generate", post(generate_otp_handler))
            .with_state(crate::DbConn(pool.clone()))
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let req = Request::builder()
            .method("POST")
            .uri("/auth/otp/generate")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
