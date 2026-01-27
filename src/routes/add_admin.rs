use crate::error::AppError;
use crate::helper::create_invite_code_admin;
use crate::routes::DBPool;
use crate::user::InviteCodeAdmin;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AddAdminRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AddAdminResponse {
    pub status: String,
    pub message: String,
}

#[tracing::instrument(skip(data, body, _user))]
#[post("/invite-codes/admins")]
pub async fn add_admin_handler(
    data: Data<DBPool>,
    body: Json<AddAdminRequest>,
    _user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
    tracing::info!("Adding new admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() || body.password.trim().is_empty() {
        return Err(AppError::InternalError(
            "Username and password cannot be empty".to_string(),
        ));
    }

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    match create_invite_code_admin(&mut conn, body.username.as_str(), body.password.as_str()) {
        Ok(_) => {
            let response = AddAdminResponse {
                status: "success".to_string(),
                message: format!("Admin user '{}' created successfully", body.username),
            };
            Ok(HttpResponse::Created().json(response))
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Err(AppError::InternalError(format!(
            "Admin user '{}' already exists",
            body.username
        ))),
        Err(e) => {
            tracing::error!("Database error creating admin: {}", e);
            Err(e.into())
        }
    }
}
