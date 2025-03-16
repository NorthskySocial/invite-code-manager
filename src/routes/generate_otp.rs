use crate::GenericResponse;
use crate::helper::{DBPool, fetch_invite_code_admin, update_otp};
use crate::routes::get_user_id;
use actix_web::web::Data;
use actix_web::{HttpResponse, Responder, post};
use diesel::row::NamedRow;
use rand::Rng;
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};

#[post("/auth/otp/generate")]
async fn generate_otp_handler(
    data: Data<DBPool>,
    session: actix_session::Session,
) -> impl Responder {
    let username: String;
    match get_user_id(session) {
        Ok(val) => username = val,
        Err(val) => return val,
    }

    let user = fetch_invite_code_admin(&mut data.get().unwrap(), username.as_str());
    let user = match user {
        None => {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: format!("No user with username: {} found", username),
            };

            return HttpResponse::NotFound().json(json_error);
        }
        Some(user) => user,
    };

    if user.otp_enabled {
        return HttpResponse::BadRequest().json(());
    }

    let mut rng = rand::thread_rng();
    let data_byte: [u8; 21] = rng.r#gen();
    let base32_string = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data_byte);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(base32_string).to_bytes().unwrap(),
    )
    .unwrap();

    let otp_base32 = totp.get_secret_base32();
    let username = username.to_owned();
    let issuer = "InviteCodeManager";
    let otp_auth_url =
        format!("otpauth://totp/{issuer}:{username}?secret={otp_base32}&issuer={issuer}");

    update_otp(
        &mut data.get().unwrap(),
        username.as_str(),
        otp_base32.as_str(),
        otp_auth_url.as_str(),
    );

    HttpResponse::Ok()
        .json(json!({"base32":otp_base32.to_owned(), "otpauth_url": otp_auth_url.to_owned()} ))
}
