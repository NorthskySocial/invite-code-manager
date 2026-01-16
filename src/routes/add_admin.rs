use crate::GenericResponse;
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
#[post("/admin/add")]
pub async fn add_admin_handler(
    data: Data<DBPool>,
    body: Json<AddAdminRequest>,
    _user: InviteCodeAdmin, // Requires authentication
) -> HttpResponse {
    tracing::info!("Adding new admin user: {}", body.username);

    // Validate input
    if body.username.trim().is_empty() || body.password.trim().is_empty() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Username and password cannot be empty".to_string(),
        };
        return HttpResponse::BadRequest().json(json_error);
    }

    match create_invite_code_admin(
        &mut data.get().unwrap(),
        body.username.as_str(),
        body.password.as_str(),
    ) {
        Ok(_) => {
            let response = AddAdminResponse {
                status: "success".to_string(),
                message: format!("Admin user '{}' created successfully", body.username),
            };
            HttpResponse::Created().json(response)
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: format!("Admin user '{}' already exists", body.username),
            };
            HttpResponse::Conflict().json(json_error)
        }
        Err(e) => {
            tracing::error!("Database error creating admin: {}", e);
            let json_error = GenericResponse {
                status: "error".to_string(),
                message: "Failed to create admin user".to_string(),
            };
            HttpResponse::InternalServerError().json(json_error)
        }
    }
}
