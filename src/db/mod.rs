use crate::DbConn;
use crate::schema::invite_code_admin::{otp_auth_url, otp_base32};
use crate::user::InviteCodeAdmin;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, SqliteConnection};

pub async fn fetch_invite_code_admin_login(
    db: &DbConn,
    _username: &str,
    _password: &str,
) -> Option<InviteCodeAdmin> {
    use crate::schema::invite_code_admin::dsl::invite_code_admin;
    use crate::schema::invite_code_admin::username;

    let _username = _username.to_string();
    let conn = db.0.get().await.expect("Db exception");
    let results: Vec<InviteCodeAdmin> = conn
        .interact(move |conn| {
            invite_code_admin
                .filter(username.eq(_username))
                .select(InviteCodeAdmin::as_select())
                .load::<InviteCodeAdmin>(conn)
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

pub fn fetch_invite_code_admin_sync(
    conn: &mut SqliteConnection,
    _username: &str,
) -> Option<InviteCodeAdmin> {
    use crate::schema::invite_code_admin::dsl::invite_code_admin;
    use crate::schema::invite_code_admin::username;
    let results = invite_code_admin
        .filter(username.eq(_username))
        .select(InviteCodeAdmin::as_select())
        .load::<InviteCodeAdmin>(conn)
        .expect("DB Exception");
    if results.is_empty() {
        None
    } else {
        Some(results.first().unwrap().clone())
    }
}

pub async fn fetch_invite_code_admin(db: &DbConn, _username: &str) -> Option<InviteCodeAdmin> {
    let _username = _username.to_string();
    let conn = db.0.get().await.expect("Db exception");
    conn.interact(move |conn| fetch_invite_code_admin_sync(conn, &_username))
        .await
        .expect("Db exception")
}

pub async fn update_otp(db: &DbConn, _username: &str, _otp_base32: &str, _otp_auth_url: &str) {
    use crate::schema::invite_code_admin;
    let _username = _username.to_string();
    let _otp_base32 = _otp_base32.to_string();
    let _otp_auth_url = _otp_auth_url.to_string();
    let conn = db.0.get().await.expect("Db exception");
    let _ = conn
        .interact(move |conn| {
            diesel::update(invite_code_admin::table)
                .filter(invite_code_admin::username.eq(_username))
                .set((
                    invite_code_admin::otp_enabled.eq(1),
                    otp_base32.eq(_otp_base32.as_str()),
                    otp_auth_url.eq(_otp_auth_url.as_str()),
                ))
                .execute(conn)
        })
        .await;
}

pub async fn verify_otp(db: &DbConn, _username: &str) {
    use crate::schema::invite_code_admin;
    let _username = _username.to_string();
    let conn = db.0.get().await.expect("Db exception");
    let _ = conn
        .interact(move |conn| {
            diesel::update(invite_code_admin::table)
                .filter(invite_code_admin::username.eq(_username))
                .set((
                    invite_code_admin::otp_verified.eq(1),
                    otp_base32.eq(otp_base32),
                    otp_auth_url.eq(otp_auth_url),
                ))
                .execute(conn)
        })
        .await;
}

pub fn create_invite_code_admin_sync(
    conn: &mut SqliteConnection,
    new_admin: &InviteCodeAdmin,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::invite_code_admin;
    diesel::insert_into(invite_code_admin::table)
        .values(new_admin)
        .execute(conn)
}

pub async fn create_invite_code_admin(
    db: &DbConn,
    _username: &str,
    _password: &str,
) -> Result<usize, diesel::result::Error> {
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

    let conn = db.0.get().await.expect("Db exception");
    conn.interact(move |conn| create_invite_code_admin_sync(conn, &new_admin))
        .await
        .expect("Db exception")
}

pub async fn delete_invite_code_admin(
    db: &DbConn,
    _username: &str,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::invite_code_admin;

    let _username = _username.to_string();
    let conn = db.0.get().await.expect("Db exception");
    conn.interact(move |conn| {
        diesel::delete(invite_code_admin::table)
            .filter(invite_code_admin::username.eq(_username))
            .execute(conn)
    })
    .await
    .expect("Db exception")
}
