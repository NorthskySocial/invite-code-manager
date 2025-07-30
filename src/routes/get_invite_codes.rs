use crate::GET_INVITE_CODES;
use crate::config::Config;
use crate::routes::InviteCodes;
use crate::user::InviteCodeAdmin;
use actix_web::web::Data;
use actix_web::{HttpResponse, Responder, get};

#[tracing::instrument(skip(config, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[get("/invite-codes")]
async fn get_invite_codes_handler(
    _invite_code_admin: InviteCodeAdmin,
    config: Data<Config>,
) -> impl Responder {
    let client = reqwest::Client::new();
    let res = match client
        .get(config.pds_endpoint.clone() + GET_INVITE_CODES)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()))
        .send()
        .await
    {
        Ok(res) => res,
        Err(_error) => return HttpResponse::InternalServerError().finish(),
    };
    if !res.status().is_success() {
        tracing::error!("not success");
        panic!("not success")
    }
    let invite_codes = res.json::<InviteCodes>().await;
    match invite_codes {
        Ok(invite_codes) => HttpResponse::Ok().json(invite_codes),
        Err(error) => {
            tracing::error!("{}", error);
            HttpResponse::InternalServerError().finish()
        }
    }
}
