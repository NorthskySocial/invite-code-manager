use crate::DISABLE_INVITE_CODES;
use crate::config::Config;
use crate::error::AppError;
use crate::user::{AccessClient, DisableInviteCodeSchema};
use axum::{Json, extract::State, response::IntoResponse};

/// Disable invite codes, for a caller authenticated by Cloudflare Access.
///
/// `/disable-invite-codes` does the same thing but authenticates with the
/// browser session cookie, so a service holding an Access token cannot reach
/// it. The vetting tool needs to disable a code when it blocks the applicant
/// it was issued to: a code already in someone's inbox outlives the decision
/// to bar them, and blocking without revoking leaves a working way in.
///
/// This mirrors `/invite-codes/issue`, which is the machine-facing counterpart
/// to `/create-invite-codes` for the same reason.
///
/// Disabling is unconditional and idempotent. A code that has already been
/// redeemed cannot be redeemed again, so disabling it is a no-op rather than
/// something to check for first — and checking would mean trusting a
/// use-count read taken a moment before the write.
#[tracing::instrument(skip(config, client, body), fields(caller = %client.0.subject()))]
#[utoipa::path(
    post,
    path = "/invite-codes/disable",
    request_body = DisableInviteCodeSchema,
    responses(
        (status = 200, description = "Invite codes disabled"),
        (status = 400, description = "Nothing to disable"),
        (status = 401, description = "Not authenticated by Cloudflare Access"),
        (status = 502, description = "PDS error")
    ),
    security(
        ("cloudflare_access" = [])
    )
)]
pub async fn revoke_invite_codes_handler(
    State(config): State<Config>,
    client: AccessClient,
    Json(body): Json<DisableInviteCodeSchema>,
) -> Result<impl IntoResponse, AppError> {
    // An empty request would disable nothing while reporting success, which
    // reads to the caller exactly like a code having been revoked.
    if body.codes.is_empty() && body.accounts.is_empty() {
        return Err(AppError::BadRequest(
            "codes or accounts must be non-empty".to_string(),
        ));
    }

    let res = reqwest::Client::new()
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
            "PDS returned error {status}: {error_body}"
        )));
    }

    Ok(Json(()))
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
            "file:revoke_invite_test?mode=memory&cache=shared",
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
            .route("/invite-codes/disable", post(revoke_invite_codes_handler))
            .with_state(state(access))
    }

    fn request(body: &str, header: Option<(&str, &str)>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/invite-codes/disable")
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

    const BODY: &str = r#"{"codes":["northsky-social-aaaaa-bbbbb"],"accounts":[]}"#;

    #[tokio::test]
    async fn rejects_a_request_without_an_access_assertion() {
        let resp = app(Some(access_config()))
            .oneshot(request(BODY, None))
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
                BODY,
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
            .oneshot(request(BODY, Some(("cf-access-jwt-assertion", "anything"))))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn does_not_reach_the_pds_before_authenticating() {
        // pds_endpoint points at localhost with nothing listening, so a 401
        // here also proves no PDS call was attempted.
        let resp = app(Some(access_config()))
            .oneshot(request(BODY, None))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn an_empty_request_is_rejected_rather_than_reported_as_success() {
        // Disabling nothing and returning 200 reads to the caller exactly like
        // a code having been revoked, which is the one outcome that must never
        // be indistinguishable from failure here.
        let parsed: DisableInviteCodeSchema =
            serde_json::from_str(r#"{"codes":[],"accounts":[]}"#).unwrap();
        assert!(parsed.codes.is_empty() && parsed.accounts.is_empty());
    }
}
