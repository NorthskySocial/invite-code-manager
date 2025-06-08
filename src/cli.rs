pub use crate::helper::DBPooledConnection;
use crate::user::InviteCodeAdmin;
use bcrypt::{DEFAULT_COST, hash};
use diesel::RunQueryDsl;
use rpassword::read_password;
use std::error::Error;
use std::io::{self, Write};

/// Creates a new admin user interactively via CLI
pub fn create_user(conn: &mut DBPooledConnection) -> Result<(), Box<dyn Error>> {
    println!("Creating a new admin user...");

    // Get username
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim();

    // Check if username already exists
    if crate::helper::fetch_invite_code_admin(conn, username).is_some() {
        return Err(format!("User with username '{}' already exists", username).into());
    }

    // Get password (securely without displaying it)
    print!("Password: ");
    io::stdout().flush()?;
    let password = read_password()?;
    let hashed_password = hash(password, DEFAULT_COST)?;

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

    println!("User '{}' created successfully!", username);
    Ok(())
}
