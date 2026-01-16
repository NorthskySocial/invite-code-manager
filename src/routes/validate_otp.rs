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
