use crate::error::AppError;
use crate::helper::delete_invite_code_admin;
use crate::routes::DBPool;
use crate::user::InviteCodeAdmin;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RemoveAdminRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveAdminResponse {
    pub status: String,
    pub message: String,
}

#[tracing::instrument(skip(data, body, user))]
#[post("/admin/remove")]
pub async fn remove_admin_handler(
    data: Data<DBPool>,
    body: Json<RemoveAdminRequest>,
    user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
    tracing::info!("Removing admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() {
        return Err(AppError::InternalError(
            "Username cannot be empty".to_string(),
        ));
    }

    // Prevent self-deletion
    if user.username == body.username {
        return Err(AppError::AuthError(
            "Cannot delete your own admin account".to_string(),
        ));
    }

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    match delete_invite_code_admin(&mut conn, body.username.as_str()) {
        Ok(rows_affected) => {
            if rows_affected > 0 {
                let response = RemoveAdminResponse {
                    status: "success".to_string(),
                    message: format!("Admin user '{}' removed successfully", body.username),
                };
                Ok(HttpResponse::Ok().json(response))
            } else {
                Err(AppError::NotFound(format!(
                    "Admin user '{}' not found",
                    body.username
                )))
            }
        }
        Err(e) => {
            tracing::error!("Database error removing admin: {}", e);
            Err(e.into())
        }
    }
}
