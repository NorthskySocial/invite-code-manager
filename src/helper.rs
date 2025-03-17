use crate::schema::invite_code_admin::{otp_auth_url, otp_base32};
use crate::user::InviteCodeAdmin;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DBPooledConnection = PooledConnection<ConnectionManager<SqliteConnection>>;

pub fn fetch_invite_code_admin(
    conn: &mut DBPooledConnection,
    _username: &str,
) -> Option<InviteCodeAdmin> {
    use crate::schema::invite_code_admin::dsl::invite_code_admin;
    use crate::schema::invite_code_admin::username;
    let results = invite_code_admin
        .filter(username.eq(_username))
        .select(InviteCodeAdmin::as_select())
        .load(conn)
        .expect("DB Exception");
    if results.is_empty() {
        None
    } else {
        Some(results.get(0).unwrap().clone())
    }
}

pub fn update_otp(
    conn: &mut DBPooledConnection,
    _username: &str,
    _otp_base32: &str,
    _otp_auth_url: &str,
) {
    use crate::schema::invite_code_admin;
    let _ = diesel::update(invite_code_admin::table)
        .filter(invite_code_admin::username.eq(_username))
        .set((
            invite_code_admin::otp_enabled.eq(1),
            invite_code_admin::otp_base32.eq(_otp_base32),
            invite_code_admin::otp_auth_url.eq(_otp_auth_url),
        ))
        .execute(conn);
}

pub fn verify_otp(conn: &mut DBPooledConnection, _username: &str) {
    use crate::schema::invite_code_admin;
    let _ = diesel::update(invite_code_admin::table)
        .filter(invite_code_admin::username.eq(_username))
        .set((
            invite_code_admin::otp_verified.eq(1),
            invite_code_admin::otp_base32.eq(otp_base32),
            invite_code_admin::otp_auth_url.eq(otp_auth_url),
        ))
        .execute(conn);
}
