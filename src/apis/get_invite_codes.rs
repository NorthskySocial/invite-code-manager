use crate::GET_ACCOUNT_INFOS;
use crate::GET_INVITE_CODES;
use crate::apis::InviteCodes;
use crate::config::Config;
use crate::error::AppError;
use crate::user::InviteCodeAdmin;
use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug)]
struct AccountInfo {
    did: String,
    handle: String,
    email: Option<String>,
    #[serde(rename = "deactivatedAt")]
    deactivated_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct AccountInfosResponse {
    infos: Vec<AccountInfo>,
}

#[tracing::instrument(skip(config, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[utoipa::path(
    get,
    path = "/invite-codes",
    responses(
        (status = 200, description = "List of invite codes retrieved successfully", body = InviteCodes),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn get_invite_codes_handler(
    State(config): State<Config>,
    _invite_code_admin: InviteCodeAdmin,
) -> Result<impl IntoResponse, AppError> {
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

        let res = request.send().await.map_err(|e| {
            tracing::error!("Request failed: {}", e);
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

        let invite_codes = res.json::<InviteCodes>().await.map_err(|e| {
            tracing::error!("Failed to parse response: {}", e);
            AppError::InternalError(e.to_string())
        })?;

        let count = invite_codes.codes.len();
        all_codes.extend(invite_codes.codes);
        cursor = invite_codes.cursor;

        if count < limit || cursor.is_none() {
            break;
        }
    }

    // Resolve handles for each account
    let mut account_dids: Vec<String> = all_codes
        .iter()
        .flat_map(|code| {
            let mut dids = vec![code.for_account.clone()];
            dids.extend(code.uses.iter().map(|u| u.used_by.clone()));
            dids
        })
        .collect();

    account_dids.sort();
    account_dids.dedup();

    let mut did_to_handle = HashMap::new();
    let mut did_to_email = HashMap::new();
    let mut did_to_deactivated = HashMap::new();
    if !account_dids.is_empty() {
        // Chunk DIDs to avoid too long query string if there are many
        for chunk in account_dids.chunks(100) {
            let query_params: Vec<(&str, String)> =
                chunk.iter().map(|did| ("dids", did.clone())).collect();

            let res = client
                .get(config.pds_endpoint.clone() + GET_ACCOUNT_INFOS)
                .query(&query_params)
                .header("Content-Type", "application/json")
                .basic_auth("admin", Some(config.pds_admin_password.clone()))
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Request for account infos failed: {}", e);
                    AppError::InternalError(e.to_string())
                })?;

            if res.status().is_success()
                && let Ok(infos) = res.json::<AccountInfosResponse>().await
            {
                for account in infos.infos {
                    did_to_email.insert(account.did.clone(), account.email);
                    did_to_deactivated
                        .insert(account.did.clone(), account.deactivated_at.is_some());
                    did_to_handle.insert(account.did, account.handle);
                }
            }
        }
    }

    for code in &mut all_codes {
        code.for_account_handle = did_to_handle.get(&code.for_account).cloned();
        for usage in &mut code.uses {
            usage.used_by_handle = did_to_handle.get(&usage.used_by).cloned();
            usage.used_by_email = did_to_email.get(&usage.used_by).cloned().flatten();
            usage.used_by_deactivated = did_to_deactivated.get(&usage.used_by).copied();
        }
    }

    Ok(Json(InviteCodes {
        cursor: None,
        codes: all_codes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::create_invite_code_admin;
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        routing::{get, post},
    };
    use diesel::RunQueryDsl;
    use tower::ServiceExt;
    use tower_sessions::Session;

    type TestDBPool = deadpool_diesel::sqlite::Pool;

    async fn setup_test_db(db_name: &str) -> TestDBPool {
        let manager = deadpool_diesel::sqlite::Manager::new(
            format!("file:{}?mode=memory&cache=shared", db_name),
            deadpool_diesel::Runtime::Tokio1,
        );
        let pool = deadpool_diesel::sqlite::Pool::builder(manager)
            .build()
            .expect("Failed to create test pool");

        let conn = pool.get().await.expect("Failed to get connection");
        conn.interact(|conn| {
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
            .execute(conn)
        })
        .await
        .expect("Interact error")
        .expect("Failed to create test table");

        pool
    }

    fn session_cookie(resp: &axum::response::Response) -> Option<String> {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|cookie| cookie.split(';').next().map(|s| s.to_string()))
    }

    async fn seed_session(session: Session) -> Result<StatusCode, AppError> {
        session
            .insert("username", "testadmin")
            .await
            .map_err(|e| AppError::InternalError(format!("Session error: {:?}", e)))?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn mock_invite_codes_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "codes": [
                {
                    "code": "northsky-123",
                    "available": 0,
                    "disabled": false,
                    "forAccount": "did:plc:owner",
                    "createdBy": "admin",
                    "createdAt": "2026-08-19T00:00:00.000Z",
                    "uses": [
                        {
                            "usedBy": "did:plc:claimer",
                            "usedAt": "2026-08-19T01:00:00.000Z"
                        }
                    ]
                }
            ]
        }))
    }

    async fn mock_account_infos_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "infos": [
                {
                    "did": "did:plc:owner",
                    "handle": "owner.test",
                    "email": "owner@example.com"
                },
                {
                    "did": "did:plc:claimer",
                    "handle": "claimer.test",
                    "email": "claimer@example.com",
                    "deactivatedAt": "2026-08-01T00:00:00.000Z"
                }
            ]
        }))
    }

    async fn mock_pds_endpoint() -> String {
        let app = Router::new()
            .route(GET_INVITE_CODES, get(mock_invite_codes_handler))
            .route(GET_ACCOUNT_INFOS, get(mock_account_infos_handler));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind mock PDS");
        let addr = listener.local_addr().expect("Failed to get mock PDS addr");

        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("Mock PDS server failed");
        });

        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_get_invite_codes_handler_unauthorized() {
        let pool = setup_test_db("get_invite_unauth").await;

        let config = Config {
            pds_admin_password: "pds_password".to_string(),
            pds_endpoint: "http://localhost".to_string(),
            access: None,
        };

        #[derive(Clone)]
        struct TestState {
            db_pool: TestDBPool,
            config: Config,
        }

        impl axum::extract::FromRef<TestState> for crate::apis::DBPool {
            fn from_ref(state: &TestState) -> crate::apis::DBPool {
                crate::DbConn(state.db_pool.clone())
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
            .route("/invite-codes", get(get_invite_codes_handler))
            .with_state(state)
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let req = Request::builder()
            .method("GET")
            .uri("/invite-codes")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_invite_codes_includes_used_by_email() {
        let pool = setup_test_db("get_invite_with_email").await;
        let db_conn = crate::DbConn(pool.clone());
        create_invite_code_admin(&db_conn, "testadmin", "password")
            .await
            .expect("Failed to create test admin");

        let config = Config {
            pds_admin_password: "pds_password".to_string(),
            pds_endpoint: mock_pds_endpoint().await,
            access: None,
        };

        #[derive(Clone)]
        struct TestState {
            db_pool: TestDBPool,
            config: Config,
        }

        impl axum::extract::FromRef<TestState> for crate::apis::DBPool {
            fn from_ref(state: &TestState) -> crate::apis::DBPool {
                crate::DbConn(state.db_pool.clone())
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
            .route("/test/seed-session", post(seed_session))
            .route("/invite-codes", get(get_invite_codes_handler))
            .with_state(state)
            .layer(tower_sessions::SessionManagerLayer::new(
                tower_sessions::MemoryStore::default(),
            ));

        let seed_req = Request::builder()
            .method("POST")
            .uri("/test/seed-session")
            .body(Body::empty())
            .unwrap();
        let seed_resp = app.clone().oneshot(seed_req).await.unwrap();
        let cookie = session_cookie(&seed_resp).expect("Expected a session cookie");

        let req = Request::builder()
            .method("GET")
            .uri("/invite-codes")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let invite_codes: InviteCodes = serde_json::from_slice(&body).unwrap();
        let usage = &invite_codes.codes[0].uses[0];

        assert_eq!(usage.used_by, "did:plc:claimer");
        assert_eq!(usage.used_by_handle.as_deref(), Some("claimer.test"));
        assert_eq!(usage.used_by_email.as_deref(), Some("claimer@example.com"));
        assert_eq!(usage.used_by_deactivated, Some(true));
    }
}
