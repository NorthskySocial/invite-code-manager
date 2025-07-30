pub use crate::helper::DBPooledConnection;
use crate::user::InviteCodeAdmin;
use argon2::Config;
use diesel::RunQueryDsl;
use rpassword::read_password;
use std::env;
use std::error::Error;
use std::io::{self, Write};

/// Creates a new admin user interactively via CLI
#[tracing::instrument(skip(conn))]
pub fn create_user(conn: &mut DBPooledConnection) -> Result<(), Box<dyn Error>> {
    tracing::info!("Creating a new admin user...");

    // Get username
    tracing::info!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    // Check if username already exists
    if crate::helper::fetch_invite_code_admin(conn, username).is_some() {
        return Err(format!("User with username '{}' already exists", username).into());
    }

    // Get password (securely without displaying it)
    tracing::info!("Password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    let salt = env::var("SALT")?;
    let config = Config::default();
    let hashed_password =
        argon2::hash_encoded(password.as_bytes(), salt.as_bytes(), &config).unwrap();

    // Create the new user
    let new_user = InviteCodeAdmin {
        username: username.to_string(),
        password: hashed_password,
        otp_base32: None,
        otp_auth_url: None,
        otp_enabled: 0,
        otp_verified: 0,
    };

    // Insert the new user into the database
    diesel::insert_into(crate::schema::invite_code_admin::table)
        .values(&new_user)
        .execute(conn)?;

    tracing::info!("User '{}' created successfully!", username);
    Ok(())
}
