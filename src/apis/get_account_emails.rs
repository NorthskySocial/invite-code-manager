use crate::GET_ACCOUNT_INFOS;
use crate::config::Config;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::{Json, extract::Query, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use std::collections::HashMap;

#[derive(Deserialize, IntoParams, Debug)]
pub struct AccountEmailsQuery {
    pub dids: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AccountEmailsResponse {
    pub emails: HashMap<String, Option<String>>,
}

#[derive(Deserialize)]
struct PdsAccountInfos {
    accounts: Vec<PdsAccountInfo>,
}

#[derive(Deserialize)]
struct PdsAccountInfo {
    did: String,
    email: Option<String>,
}

#[tracing::instrument(skip(config, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[utoipa::path(
    get,
    path = "/account/emails",
    params(
        ("dids" = Vec<String>, Query, description = "List of DIDs to fetch emails for")
    ),
    responses(
        (status = 200, description = "Account emails retrieved successfully", body = AccountEmailsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn get_account_emails_handler(
    State(config): State<Config>,
    _invite_code_admin: InviteCodeAdmin,
    Query(query): Query<AccountEmailsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let client = reqwest::Client::new();

    let mut request = client
        .get(config.pds_endpoint.clone() + GET_ACCOUNT_INFOS)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()));
    
    for did in &query.dids {
        request = request.query(&[("dids", did)]);
    }

    let res = request
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Request for account infos failed: {}", e);
            AppError::InternalError(e.to_string())
        })?;

    if !res.status().is_success() {
        let status = res.status();
        tracing::error!("PDS returned error: status {}", status);
        return Err(AppError::PdsError(format!(
            "PDS returned error: status {}",
            status
        )));
    }

    let pds_infos = res.json::<PdsAccountInfos>().await.map_err(|e| {
        tracing::error!("Failed to parse PDS response: {}", e);
        AppError::InternalError(e.to_string())
    })?;

    let mut emails = HashMap::new();
    for account in pds_infos.accounts {
        emails.insert(account.did, account.email);
    }

    // Ensure all requested DIDs are in the response, even if missing from PDS
    for did in query.dids {
        if !emails.contains_key(&did) {
            emails.insert(did, None);
        }
    }

    Ok(Json(AccountEmailsResponse { emails }))
}
