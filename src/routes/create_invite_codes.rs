use crate::CREATE_INVITE_CODES;
use crate::config::Config;
use crate::user::{CreateInviteCodeSchema, InviteCodeAdmin};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};

#[tracing::instrument(skip(config, body, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[post("/create-invite-codes")]
async fn create_invite_codes_handler(
    _invite_code_admin: InviteCodeAdmin,
    config: Data<Config>,
    body: Json<CreateInviteCodeSchema>,
) -> HttpResponse {
    let client = reqwest::Client::new();
    let res = match client
        .post(config.pds_endpoint.clone() + CREATE_INVITE_CODES)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()))
        .json(&body)
        .send()
        .await
    {
        Ok(res) => res,
        Err(_error) => return HttpResponse::InternalServerError().finish(),
    };
    if !res.status().is_success() {
        panic!("not success")
    }

    HttpResponse::Ok().json(())
}
