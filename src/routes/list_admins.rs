use crate::error::AppError;
use crate::routes::{DBPool, invite_code_admin_to_response};
use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use actix_web::web::Data;
use actix_web::{HttpResponse, get};
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ListAdminsResponse {
    pub status: String,
    pub admins: Vec<InviteCodeAdminData>,
}

#[tracing::instrument(skip(data, _user))]
#[utoipa::path(
    get,
    path = "/admins",
    responses(
        (status = 200, description = "List of admin users retrieved successfully", body = ListAdminsResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
#[get("/admins")]
pub async fn list_admins_handler(
    data: Data<DBPool>,
    _user: InviteCodeAdmin, // Requires authentication
) -> Result<HttpResponse, AppError> {
    tracing::info!("Listing all admin users");

    let mut conn = data
        .get()
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    use crate::schema::invite_code_admin::dsl::invite_code_admin;

    let results = invite_code_admin
        .select(InviteCodeAdmin::as_select())
        .load::<InviteCodeAdmin>(&mut conn)
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let admins_data: Vec<InviteCodeAdminData> =
        results.iter().map(invite_code_admin_to_response).collect();

    let response = ListAdminsResponse {
        status: "success".to_string(),
        admins: admins_data,
    };

    Ok(HttpResponse::Ok().json(response))
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
    async fn test_list_admins_handler_unauthorized() {
        let pool = setup_test_db("list_admins_unauth");

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
                .service(list_admins_handler),
        )
        .await;

        let req = test::TestRequest::get().uri("/admins").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
