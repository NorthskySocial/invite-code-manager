use crate::DbConn;
use crate::schema::invite_code_admin::{otp_auth_url, otp_base32};
use crate::user::InviteCodeAdmin;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};

pub async fn fetch_invite_code_admin_login(
    conn: &mut DbConn,
    _username: &str,
    _password: &str,
) -> Option<InviteCodeAdmin> {
    use crate::schema::invite_code_admin::dsl::invite_code_admin;
    use crate::schema::invite_code_admin::username;

    let results = conn
        .0
        .get()
        .await
        .expect("Db exception")
        .interact(move |conn| {
            invite_code_admin
                .filter(username.eq(_username))
                .select(InviteCodeAdmin::as_select())
                .load(conn)
                .expect("DB Exception")
        })
        .await
        .expect("Db exception");

    if results.is_empty() {
        None
    } else {
        let user = results.first().unwrap().clone();
        let user_password = user.password.clone();
        match argon2::verify_encoded(user_password.as_str(), _password.as_ref()).unwrap() {
            true => Some(user),
            false => None,
        }
    }
}

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
        Some(results.first().unwrap().clone())
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
            otp_base32.eq(_otp_base32),
            otp_auth_url.eq(_otp_auth_url),
        ))
        .execute(conn);
}

pub fn verify_otp(conn: &mut DBPooledConnection, _username: &str) {
    use crate::schema::invite_code_admin;
    let _ = diesel::update(invite_code_admin::table)
        .filter(invite_code_admin::username.eq(_username))
        .set((
            invite_code_admin::otp_verified.eq(1),
            otp_base32.eq(otp_base32),
            otp_auth_url.eq(otp_auth_url),
        ))
        .execute(conn);
}

pub fn create_invite_code_admin(
    conn: &mut DBPooledConnection,
    _username: &str,
    _password: &str,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::invite_code_admin;
    use crate::user::InviteCodeAdmin;

    // Hash the password using Argon2
    let hashed_password = argon2::hash_encoded(
        _password.as_bytes(),
        b"randomsalt",
        &argon2::Config::default(),
    )
    .map_err(|_| diesel::result::Error::RollbackTransaction)?;

    let new_admin = InviteCodeAdmin {
        username: _username.to_string(),
        password: hashed_password,
        otp_base32: None,
        otp_auth_url: None,
        otp_enabled: 0,
        otp_verified: 0,
    };

    diesel::insert_into(invite_code_admin::table)
        .values(&new_admin)
        .execute(conn)
}

pub fn delete_invite_code_admin(
    conn: &mut DBPooledConnection,
    _username: &str,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::invite_code_admin;

    diesel::delete(invite_code_admin::table)
        .filter(invite_code_admin::username.eq(_username))
        .execute(conn)
}
