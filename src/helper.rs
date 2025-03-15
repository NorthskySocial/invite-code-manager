use crate::user::InviteCodeAdmin;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DBPooledConnection = PooledConnection<ConnectionManager<SqliteConnection>>;

pub fn create_invite_code_admin(conn: &mut DBPooledConnection, username: &str, password: &str) {
    use crate::schema::invite_code_admin;
    let invite_code_admin = InviteCodeAdmin {
        username: username.to_string(),
        password: password.to_string(),
        otp_base32: None,
        otp_auth_url: None,
        otp_enabled: 0,
        otp_verified: 0,
    };

    let _ = diesel::insert_into(invite_code_admin::table)
        .values(&invite_code_admin)
        .execute(conn);
}

pub fn fetch_invite_code_admin(
    conn: &mut DBPooledConnection,
    _username: &str,
) -> Option<InviteCodeAdmin> {
    use crate::schema::invite_code_admin::dsl::invite_code_admin;
    use crate::schema::invite_code_admin::username;
    let mut results = invite_code_admin
        .filter(username.eq(username))
        .select(InviteCodeAdmin::as_select())
        .load(conn)
        .expect("DB Exception");
    if results.is_empty() {
        None
    } else {
        Some(results.get(0).unwrap().clone())
    }
}