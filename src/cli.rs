use crate::db::{DBPooledConnection, fetch_invite_code_admin};
use crate::schema::invite_code_admin::dsl::invite_code_admin;
use crate::user::InviteCodeAdmin;
use argon2::Config;
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
use rpassword::read_password;
use std::env;
use std::error::Error;
use std::io::{self, Write};

/// Creates a new admin user interactively via CLI
#[tracing::instrument(skip(conn))]
pub fn create_user(conn: &mut DBPooledConnection) -> Result<(), Box<dyn Error>> {
    tracing::info!("Creating a new admin user...");

    // Get username
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    // Check if username already exists
    if fetch_invite_code_admin(conn, username).is_some() {
        return Err(format!("User with username '{}' already exists", username).into());
    }

    // Get password (securely without displaying it)
    print!("Password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    let salt = env::var("SALT")?;
    if salt.is_empty() {
        return Err("SALT environment variable is not set or is empty".into());
    }
    if salt.len() < 8 {
        return Err("SALT must be at least 8 characters long".into());
    }

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

/// Lists all admin users
#[tracing::instrument(skip(conn))]
pub fn list_users(conn: &mut DBPooledConnection) -> Result<(), Box<dyn Error>> {
    tracing::info!("Listing all admin users...");

    let users = invite_code_admin
        .select(InviteCodeAdmin::as_select())
        .load(conn)?;

    if users.is_empty() {
        println!("No users found.");
        return Ok(());
    }

    println!(
        "{:<20} {:<12} {:<12}",
        "Username", "OTP Enabled", "OTP Verified"
    );
    println!("{:-<44}", "");

    for user in users {
        println!(
            "{:<20} {:<12} {:<12}",
            user.username,
            if user.otp_enabled == 1 { "Yes" } else { "No" },
            if user.otp_verified == 1 { "Yes" } else { "No" }
        );
    }

    Ok(())
}
