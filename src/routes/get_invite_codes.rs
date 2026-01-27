use crate::GET_INVITE_CODES;
use crate::config::Config;
use crate::routes::InviteCodes;
use crate::user::InviteCodeAdmin;
use actix_web::web::Data;
use actix_web::{HttpResponse, Responder, get};

#[tracing::instrument(skip(config, _invite_code_admin), fields(user_id = %_invite_code_admin.username
))]
#[utoipa::path(
    get,
    path = "/invite-codes",
    responses(
        (status = 200, description = "List of invite codes retrieved successfully", body = InviteCodes),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
#[get("/invite-codes")]
pub async fn get_invite_codes_handler(
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
    async fn test_get_invite_codes_handler_unauthorized() {
        let pool = setup_test_db("get_invite_unauth");

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
                .service(get_invite_codes_handler),
        )
        .await;

        let req = test::TestRequest::get().uri("/invite-codes").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
