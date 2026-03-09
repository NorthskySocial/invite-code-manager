use crate::GET_ACCOUNT_INFO;
use crate::config::Config;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::{Json, extract::Query, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, IntoParams, Debug)]
pub struct AccountEmailQuery {
    pub did: String,
}

#[derive(Serialize, ToSchema)]
pub struct AccountEmailResponse {
    pub email: Option<String>,
}

#[derive(Deserialize)]
struct PdsAccountInfo {
    email: Option<String>,
}

#[tracing::instrument(skip(config, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[utoipa::path(
    get,
    path = "/account/email",
    params(
        AccountEmailQuery
    ),
    responses(
        (status = 200, description = "Account email retrieved successfully", body = AccountEmailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn get_account_email_handler(
    State(config): State<Config>,
    _invite_code_admin: InviteCodeAdmin,
    Query(query): Query<AccountEmailQuery>,
) -> Result<impl IntoResponse, AppError> {
    let client = reqwest::Client::new();

    let res = client
        .get(config.pds_endpoint.clone() + GET_ACCOUNT_INFO)
        .query(&[("did", query.did)])
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Request for account info failed: {}", e);
            AppError::InternalError(e.to_string())
        })?;

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::NotFound("Account not found".to_string()));
    }

    if !res.status().is_success() {
        let status = res.status();
        tracing::error!("PDS returned error: status {}", status);
        return Err(AppError::PdsError(format!(
            "PDS returned error: status {}",
            status
        )));
    }

    let pds_info = res.json::<PdsAccountInfo>().await.map_err(|e| {
        tracing::error!("Failed to parse PDS response: {}", e);
        AppError::InternalError(e.to_string())
    })?;

    Ok(Json(AccountEmailResponse {
        email: pds_info.email,
    }))
}
