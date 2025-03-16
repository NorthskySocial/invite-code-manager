use crate::CREATE_INVITE_CODES;
use crate::config::Config;
use crate::helper::DBPool;
use crate::routes::InviteCodes;
use crate::user::{CreateInviteCodeSchema, InviteCodeAdmin};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};
use serde_json::json;

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
        Err(error) => return HttpResponse::InternalServerError().finish(),
    };
    if !res.status().is_success() {
        panic!("not success")
    }
    let invite_codes = res.json::<InviteCodes>().await;
    match invite_codes {
        Ok(invite_codes) => {
            // codes_tx.send(invite_codes).unwrap();
        }
        Err(error) => {
            eprintln!("{}", error);
            return HttpResponse::InternalServerError().finish();
        }
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}
