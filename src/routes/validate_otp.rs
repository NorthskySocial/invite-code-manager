use crate::GenericResponse;
use crate::helper::DBPool;
use crate::user::{InviteCodeAdmin, VerifyOTPSchema};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, Responder, post};
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[post("/auth/otp/validate")]
async fn validate_otp_handler(
    body: Json<VerifyOTPSchema>,
    data: Data<DBPool>,
    invite_code_admin: InviteCodeAdmin,
    session: actix_session::Session,
) -> impl Responder {
    if !invite_code_admin.otp_enabled.eq(&1) {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = invite_code_admin.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    session
        .insert("otp_validated", invite_code_admin.username.clone())
        .expect("User ID failed to insert");
    HttpResponse::Ok().json(json!({"otp_valid": true}))
}
