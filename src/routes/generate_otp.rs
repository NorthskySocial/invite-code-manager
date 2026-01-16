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
