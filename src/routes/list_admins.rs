use crate::error::AppError;
use crate::routes::{DBPool, invite_code_admin_to_response};
use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use actix_web::web::Data;
use actix_web::{HttpResponse, get};
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ListAdminsResponse {
    pub status: String,
    pub admins: Vec<InviteCodeAdminData>,
}

#[tracing::instrument(skip(data, _user))]
#[get("/invite-codes/admins")]
pub async fn list_admins_handler(
    data: Data<DBPool>,
    _user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
    tracing::info!("Listing all admin users");

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    use crate::schema::invite_code_admin::dsl::invite_code_admin;

    let results = invite_code_admin
        .select(InviteCodeAdmin::as_select())
        .load::<InviteCodeAdmin>(&mut conn)
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let admins_data: Vec<InviteCodeAdminData> =
        results.iter().map(invite_code_admin_to_response).collect();

    let response = ListAdminsResponse {
        status: "success".to_string(),
        admins: admins_data,
    };

    Ok(HttpResponse::Ok().json(response))
}
