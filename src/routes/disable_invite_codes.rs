use crate::DISABLE_INVITE_CODES;
use crate::config::Config;
use crate::error::AppError;
use crate::user::{DisableInviteCodeSchema, InviteCodeAdmin};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};

#[tracing::instrument(skip(config, body, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[post("/disable-invite-codes")]
async fn disable_invite_codes_handler(
    _invite_code_admin: InviteCodeAdmin,
    body: Json<DisableInviteCodeSchema>,
    config: Data<Config>,
) -> Result<HttpResponse, AppError> {
    let client = reqwest::Client::new();
    let res = client
        .post(config.pds_endpoint.clone() + DISABLE_INVITE_CODES)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()))
        .json(&body)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let error_body = res.text().await.unwrap_or_default();
        return Err(AppError::PdsError(format!(
            "PDS returned error {}: {}",
            status, error_body
        )));
    }

    Ok(HttpResponse::Ok().finish())
}
