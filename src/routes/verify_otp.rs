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
