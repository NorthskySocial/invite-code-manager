use crate::DISABLE_INVITE_CODES;
use crate::config::Config;
use crate::user::{DisableInviteCodeSchema, InviteCodeAdmin};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};

#[post("/disable-invite-codes")]
async fn disable_invite_codes_handler(
    _invite_code_admin: InviteCodeAdmin,
    body: Json<DisableInviteCodeSchema>,
    config: Data<Config>,
) -> HttpResponse {
    let client = reqwest::Client::new();
    let res = match client
        .post(config.pds_endpoint.clone() + DISABLE_INVITE_CODES)
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
        return HttpResponse::InternalServerError().finish();
    }

    HttpResponse::Ok().finish()
}
