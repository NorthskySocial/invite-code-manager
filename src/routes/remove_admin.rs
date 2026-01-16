use crate::GenericResponse;
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
) -> HttpResponse {
    tracing::info!("Removing admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Username cannot be empty".to_string(),
        };
        return HttpResponse::BadRequest().json(json_error);
    }

    // Prevent self-deletion
    if user.username == body.username {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Cannot delete your own admin account".to_string(),
        };
        return HttpResponse::Forbidden().json(json_error);
    }

    match delete_invite_code_admin(&mut data.get().unwrap(), body.username.as_str()) {
        Ok(rows_affected) => {
            if rows_affected > 0 {
                let response = RemoveAdminResponse {
                    status: "success".to_string(),
                    message: format!("Admin user '{}' removed successfully", body.username),
                };
                HttpResponse::Ok().json(response)
            } else {
                let json_error = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Admin user '{}' not found", body.username),
                };
                HttpResponse::NotFound().json(json_error)
            }
        }
        Err(e) => {
            tracing::error!("Database error removing admin: {}", e);
            let json_error = GenericResponse {
                status: "error".to_string(),
                message: "Failed to remove admin user".to_string(),
            };
            HttpResponse::InternalServerError().json(json_error)
        }
    }
}
