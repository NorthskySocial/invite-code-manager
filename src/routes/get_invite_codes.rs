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
    let mut all_codes = Vec::new();
    let mut cursor: Option<String> = None;
    let limit = 500;

    loop {
        let mut request = client
            .get(config.pds_endpoint.clone() + GET_INVITE_CODES)
            .query(&[("limit", limit.to_string())])
            .header("Content-Type", "application/json")
            .basic_auth("admin", Some(config.pds_admin_password.clone()));

        if let Some(ref c) = cursor {
            request = request.query(&[("cursor", c)]);
        }

        let res = match request.send().await {
            Ok(res) => res,
            Err(error) => {
                tracing::error!("Request failed: {}", error);
                return HttpResponse::InternalServerError().finish();
            }
        };

        if !res.status().is_success() {
            tracing::error!("PDS returned error: status {}", res.status());
            return HttpResponse::InternalServerError().finish();
        }

        let invite_codes_res = res.json::<InviteCodes>().await;
        match invite_codes_res {
            Ok(invite_codes) => {
                let count = invite_codes.codes.len();
                all_codes.extend(invite_codes.codes);
                cursor = invite_codes.cursor;

                if count < limit || cursor.is_none() {
                    break;
                }
            }
            Err(error) => {
                tracing::error!("Failed to parse response: {}", error);
                return HttpResponse::InternalServerError().finish();
            }
        }
    }

    HttpResponse::Ok().json(InviteCodes {
        cursor: None,
        codes: all_codes,
    })
}
