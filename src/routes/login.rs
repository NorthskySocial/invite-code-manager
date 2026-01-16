use crate::LoginUser;
use crate::error::AppError;
use crate::helper::fetch_invite_code_admin_login;
use crate::routes::{DBPool, invite_code_admin_to_response};
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
) -> Result<HttpResponse, AppError> {
    tracing::info!("Login user");
    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    let user =
        fetch_invite_code_admin_login(&mut conn, body.username.as_str(), body.password.as_str());
    match user {
        None => Err(AppError::AuthError(format!(
            "Invalid username or password for: {}",
            body.username
        ))),
        Some(user) => {
            session.renew();
            session
                .insert("username", body.username.clone())
                .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;

            if user.otp_verified == 1 {
                session
                    .insert("otp_enabled", "y")
                    .map_err(|e| AppError::InternalError(format!("Session error: {}", e)))?;
                let response = invite_code_admin_to_response(&user);
                Ok(HttpResponse::Ok().json(response))
            } else {
                let response = invite_code_admin_to_response(&user);
                Ok(HttpResponse::Created().json(response))
            }
        }
    }
}
