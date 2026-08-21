use crate::CREATE_INVITE_CODE;
use crate::config::Config;
use crate::error::AppError;
use crate::user::{AccessClient, IssueInviteCodeResponse, IssueInviteCodeSchema};
use axum::{Json, extract::State, response::IntoResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct PdsInviteCode {
    code: String,
}

/// Create a single invite code and return it.
///
/// `/create-invite-codes` calls the PDS's *plural* endpoint, which reports only
/// success — leaving a caller who needs a specific applicant's code to list
/// every code on the PDS and diff against what it saw before. That is both
/// expensive and racy when two callers create codes at once.
///
/// The singular `com.atproto.server.createInviteCode` returns the code it made,
/// so one call is enough and no diffing is involved.
#[tracing::instrument(skip(config, client, body), fields(caller = %client.0.subject()))]
#[utoipa::path(
    post,
    path = "/invite-codes/issue",
    request_body = IssueInviteCodeSchema,
    responses(
        (status = 200, description = "Invite code created", body = IssueInviteCodeResponse),
        (status = 400, description = "Invalid useCount"),
        (status = 401, description = "Not authenticated by Cloudflare Access"),
        (status = 502, description = "PDS error")
    ),
    security(
        ("cloudflare_access" = [])
    )
)]
pub async fn issue_invite_code_handler(
    State(config): State<Config>,
    client: AccessClient,
    Json(body): Json<IssueInviteCodeSchema>,
) -> Result<impl IntoResponse, AppError> {
    if body.use_count < 1 {
        return Err(AppError::BadRequest(
            "useCount must be at least 1".to_string(),
        ));
    }

    let res = reqwest::Client::new()
        .post(config.pds_endpoint.clone() + CREATE_INVITE_CODE)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some(config.pds_admin_password.clone()))
        .json(&serde_json::json!({ "useCount": body.use_count }))
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let error_body = res.text().await.unwrap_or_default();
        return Err(AppError::PdsError(format!(
            "PDS returned error {status}: {error_body}"
        )));
    }

    let created: PdsInviteCode = res
        .json()
        .await
        .map_err(|e| AppError::PdsError(format!("PDS returned no usable code: {e}")))?;

    // The code itself is never logged: it is a credential, and this line exists
    // so an issued code can be attributed to a caller after the fact.
    tracing::info!(
        caller = %client.0.subject(),
        use_count = body.use_count,
        "issued an invite code"
    );

    Ok(Json(IssueInviteCodeResponse {
        code: created.code,
        use_count: body.use_count,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbConn;
    use crate::state::AppState;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use tower::ServiceExt;

    fn state(access: Option<crate::access::AccessConfig>) -> AppState {
        let manager = deadpool_diesel::sqlite::Manager::new(
            "file:issue_invite_test?mode=memory&cache=shared",
            deadpool_diesel::Runtime::Tokio1,
        );
        let pool = deadpool_diesel::sqlite::Pool::builder(manager)
            .build()
            .expect("Failed to create test pool");

        AppState {
            db_pool: DbConn(pool),
            config: Config {
                pds_admin_password: "pds_password".to_string(),
                pds_endpoint: "http://localhost".to_string(),
                access,
            },
        }
    }

    fn app(access: Option<crate::access::AccessConfig>) -> Router {
        Router::new()
            .route("/invite-codes/issue", post(issue_invite_code_handler))
            .with_state(state(access))
    }

    fn request(body: &str, header: Option<(&str, &str)>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/invite-codes/issue")
            .header("content-type", "application/json");

        if let Some((name, value)) = header {
            builder = builder.header(name, value);
        }

        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn access_config() -> crate::access::AccessConfig {
        crate::access::AccessConfig::new(
            "https://team.cloudflareaccess.com".to_string(),
            "aud-tag".to_string(),
            vec![],
        )
    }

    #[tokio::test]
    async fn rejects_a_request_without_an_access_assertion() {
        let resp = app(Some(access_config()))
            .oneshot(request(r#"{"useCount":1}"#, None))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_a_forged_access_assertion() {
        // A caller reaching the origin directly can set any header it likes;
        // only a signature from the team's Access keys is trusted.
        let resp = app(Some(access_config()))
            .oneshot(request(
                r#"{"useCount":1}"#,
                Some(("cf-access-jwt-assertion", "totally.made.up")),
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refuses_every_request_when_access_is_not_configured() {
        // Fail closed: an unconfigured auth path must not become an open one.
        let resp = app(None)
            .oneshot(request(
                r#"{"useCount":1}"#,
                Some(("cf-access-jwt-assertion", "anything")),
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn does_not_reach_the_pds_before_authenticating() {
        // pds_endpoint points at localhost with nothing listening, so a 401
        // here also proves no PDS call was attempted.
        let resp = app(Some(access_config()))
            .oneshot(request(r#"{"useCount":500}"#, None))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn use_count_defaults_to_one() {
        let parsed: IssueInviteCodeSchema = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.use_count, 1);
    }

    #[test]
    fn use_count_is_read_when_given() {
        let parsed: IssueInviteCodeSchema = serde_json::from_str(r#"{"useCount":5}"#).unwrap();
        assert_eq!(parsed.use_count, 5);
    }
}
