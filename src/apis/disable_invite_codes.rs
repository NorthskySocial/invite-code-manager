use crate::DISABLE_INVITE_CODES;
use crate::config::Config;
use crate::error::AppError;
use crate::user::{DisableInviteCodeSchema, InviteCodeAdmin};
use axum::{Json, extract::State, response::IntoResponse};

#[tracing::instrument(skip(config, _invite_code_admin, body), fields(user_id = %_invite_code_admin.username
))]
#[utoipa::path(
    post,
    path = "/disable-invite-codes",
    request_body = DisableInviteCodeSchema,
    responses(
        (status = 200, description = "Invite codes disabled successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 502, description = "PDS error")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn disable_invite_codes_handler(
    State(config): State<Config>,
    _invite_code_admin: InviteCodeAdmin,
    Json(body): Json<DisableInviteCodeSchema>,
) -> Result<impl IntoResponse, AppError> {
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

    Ok(Json(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::post,
    };
    use diesel::RunQueryDsl;
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};
    use tower::ServiceExt;

    type TestDBPool = Pool<ConnectionManager<SqliteConnection>>;

    fn setup_test_db(db_name: &str) -> TestDBPool {
        let manager = ConnectionManager::<SqliteConnection>::new(format!(
            "file:{}?mode=memory&cache=shared",
            db_name
        ));
        let pool = Pool::builder()
            .build(manager)
            .expect("Failed to create test pool");

        let mut conn = pool.get().expect("Failed to get connection");
        diesel::sql_query(
            "CREATE TABLE invite_code_admin (
                rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otp_base32 TEXT,
                otp_auth_url TEXT,
                otp_enabled INTEGER NOT NULL DEFAULT 0,
                otp_verified INTEGER NOT NULL DEFAULT 0
            );",
        )
        .execute(&mut conn)
        .expect("Failed to create test table");

        pool
    }

    #[tokio::test]
    async fn test_disable_invite_codes_handler_unauthorized() {
        let pool = setup_test_db("disable_invite_unauth");

        let config = Config {
            pds_admin_password: "pds_password".to_string(),
            pds_endpoint: "http://localhost".to_string(),
        };

        #[derive(Clone)]
        struct TestState {
            db_pool: TestDBPool,
            config: Config,
        }

        impl axum::extract::FromRef<TestState> for crate::apis::DBPool {
            fn from_ref(state: &TestState) -> crate::apis::DBPool {
                state.db_pool.clone()
            }
        }

        impl axum::extract::FromRef<TestState> for Config {
            fn from_ref(state: &TestState) -> Config {
                state.config.clone()
            }
        }

        let state = TestState {
            db_pool: pool,
            config,
        };

        let app = Router::new()
            .route("/disable-invite-codes", post(disable_invite_codes_handler))
            .with_state(state)
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let payload = DisableInviteCodeSchema {
            codes: vec!["code1".to_string()],
            accounts: vec!["acc1".to_string()],
        };

        let req = Request::builder()
            .method("POST")
            .uri("/disable-invite-codes")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
