use crate::schema::invite_code_admin::dsl::invite_code_admin;
use crate::user::InviteCodeAdmin;
use diesel::SqliteConnection;
use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
use rpassword::read_password;
use std::error::Error;
use std::io::{self, Write};

/// Creates a new admin user interactively via CLI
#[tracing::instrument(skip(conn))]
pub fn create_user(conn: &mut SqliteConnection) -> Result<(), Box<dyn Error>> {
    tracing::info!("Creating a new admin user...");

    // Get username
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    // Check if username already exists
    if crate::db::fetch_invite_code_admin_sync(conn, username).is_some() {
        return Err(format!("User with username '{}' already exists", username).into());
    }

    // Get password (securely without displaying it)
    print!("Password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    let new_user = crate::db::build_invite_code_admin(username, &password)?;
    crate::db::create_invite_code_admin_sync(conn, &new_user)?;

    tracing::info!("User '{}' created successfully!", username);
    Ok(())
}

/// Lists all admin users
#[tracing::instrument(skip(conn))]
pub fn list_users(conn: &mut SqliteConnection) -> Result<(), Box<dyn Error>> {
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
