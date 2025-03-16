use crate::helper::{verify_otp, DBPool};
use crate::routes::invite_code_admin_to_response;
use crate::user::{InviteCodeAdmin, VerifyOTPSchema};
use crate::GenericResponse;
use actix_web::web::{Data, Json};
use actix_web::{post, HttpResponse, Responder};
use diesel::row::NamedRow;
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[post("/auth/otp/verify")]
async fn verify_otp_handler(
    body: Json<VerifyOTPSchema>,
    data: Data<DBPool>,
    invite_code_admin: InviteCodeAdmin,
    session: actix_session::Session,
) -> impl Responder {
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
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Token is invalid or user doesn't exist".to_string(),
        };

        return HttpResponse::Forbidden().json(json_error);
    }

    verify_otp(
        &mut data.get().unwrap(),
        invite_code_admin.username.as_str(),
    );

    session
        .insert("otp_validated", invite_code_admin.username.clone())
        .expect("User ID failed to insert");

    HttpResponse::Ok().json(
        json!({"otp_verified": true, "user": invite_code_admin_to_response(&invite_code_admin)}),
    )
}
