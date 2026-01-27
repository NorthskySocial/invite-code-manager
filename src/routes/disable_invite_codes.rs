use crate::DISABLE_INVITE_CODES;
use crate::config::Config;
use crate::error::AppError;
use crate::user::{DisableInviteCodeSchema, InviteCodeAdmin};
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, post};

#[tracing::instrument(skip(config, body, _invite_code_admin), fields(user_id = %_invite_code_admin.username
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
#[post("/disable-invite-codes")]
pub async fn disable_invite_codes_handler(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use actix_session::SessionMiddleware;
    use actix_session::storage::CookieSessionStore;
    use actix_web::{App, cookie::Key, test};
    use diesel::RunQueryDsl;
    use diesel::SqliteConnection;
    use diesel::r2d2::{ConnectionManager, Pool};

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

    #[actix_web::test]
    async fn test_disable_invite_codes_handler_unauthorized() {
        let pool = setup_test_db("disable_invite_unauth");

        let secret_key = Key::generate();
        let config = Config {
            pds_admin_password: "pds_password".to_string(),
            pds_endpoint: "http://localhost".to_string(),
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(pool.clone()))
                .app_data(Data::new(config.clone()))
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    secret_key.clone(),
                ))
                .service(disable_invite_codes_handler),
        )
        .await;

        let payload = DisableInviteCodeSchema {
            codes: vec!["code1".to_string()],
            accounts: vec!["acc1".to_string()],
        };

        let req = test::TestRequest::post()
            .uri("/disable-invite-codes")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
