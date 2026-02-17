use crate::error::AppError;
use crate::user::{InviteCodeAdmin, VerifyOTPSchema};
use axum::{Json, response::IntoResponse};
use serde::Serialize;
use totp_rs::{Algorithm, Secret, TOTP};
use tower_sessions::Session;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct ValidateOTPResponse {
    pub otp_valid: bool,
}

#[tracing::instrument(skip(session, invite_code_admin, body), fields(user_id = %invite_code_admin.username
))]
#[utoipa::path(
    post,
    path = "/auth/otp/validate",
    request_body = VerifyOTPSchema,
    responses(
        (status = 200, description = "OTP validated successfully", body = ValidateOTPResponse),
        (status = 401, description = "Unauthorized or invalid token")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn validate_otp_handler(
    session: Session,
    invite_code_admin: InviteCodeAdmin,
    Json(body): Json<VerifyOTPSchema>,
) -> Result<impl IntoResponse, AppError> {
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
        .insert("otp_validated", "y")
        .await
        .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;

    Ok(Json(ValidateOTPResponse { otp_valid: true }))
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
    async fn test_validate_otp_handler_unauthorized() {
        let db_name = "validate_otp_unauth";
        let pool = setup_test_db(db_name).await;

        let app = Router::new()
            .route("/auth/otp/validate", post(validate_otp_handler))
            .with_state(crate::DbConn(pool.clone()))
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let payload = VerifyOTPSchema {
            token: "000000".to_string(),
        };

        let req = Request::builder()
            .method("POST")
            .uri("/auth/otp/validate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
