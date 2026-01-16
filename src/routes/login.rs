use crate::helper::fetch_invite_code_admin_login;
use crate::routes::{DBPool, invite_code_admin_to_response};
use crate::{GenericResponse, LoginUser};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub status: String,
}

#[tracing::instrument(skip(data, body, session))]
#[post("/auth/login")]
async fn login_user(
    data: Data<DBPool>,
    body: Json<LoginUser>,
    session: actix_session::Session,
) -> HttpResponse {
    tracing::info!("Login user");
    let user = fetch_invite_code_admin_login(
        &mut data.get().unwrap(),
        body.username.as_str(),
        body.password.as_str(),
    );
    match user {
        None => {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: format!("No user with username: {} found", body.username),
            };

            HttpResponse::NotFound().json(json_error)
        }
        Some(user) => {
            session.renew();
            session
                .insert("username", body.username.clone())
                .expect("Username failed to insert");
            if user.otp_verified == 1 {
                session
                    .insert("otp_enabled", "y")
                    .expect("OTP failed to insert");
                let response = invite_code_admin_to_response(&user);
                HttpResponse::Ok().json(response)
            } else {
                let response = invite_code_admin_to_response(&user);
                HttpResponse::Created().json(response)
            }
        }
    }
}
