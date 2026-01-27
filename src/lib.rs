extern crate alloc;
extern crate core;

pub mod cli;
pub mod config;
pub mod error;
pub mod helper;
pub mod routes;
pub mod schema;
pub mod user;

use alloc::string::String;

use utoipa::ToSchema;

// Shared structures that are used across modules
#[derive(serde::Deserialize, Debug, serde::Serialize, ToSchema)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

// Constants used by routes
pub const GET_INVITE_CODES: &str = "/xrpc/com.atproto.admin.getInviteCodes";
pub const DISABLE_INVITE_CODES: &str = "/xrpc/com.atproto.admin.disableInviteCodes";
pub const CREATE_INVITE_CODES: &str = "/xrpc/com.atproto.server.createInviteCodes";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::{
        create_invite_code_admin, delete_invite_code_admin, fetch_invite_code_admin,
        fetch_invite_code_admin_login,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use core::{assert, assert_eq, assert_ne};
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{RunQueryDsl, SqliteConnection};

    type TestDBPool = Pool<ConnectionManager<SqliteConnection>>;

    fn setup_test_db() -> TestDBPool {
        let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
        let pool = Pool::builder()
            .min_idle(Some(1))
            .build(manager)
            .expect("Failed to create test pool");

        // Run migrations on the test database
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

    #[test]
    fn test_basic_functionality() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_config_creation() {
        let config = config::Config {
            pds_admin_password: "test_password".to_string(),
            pds_endpoint: "http://test-endpoint".to_string(),
        };
        assert_eq!(config.pds_admin_password, "test_password");
        assert_eq!(config.pds_endpoint, "http://test-endpoint");
    }

    #[test]
    fn test_create_invite_code_admin_success() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        let result = create_invite_code_admin(&mut conn, "testuser", "testpass");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Should insert 1 row
    }

    #[test]
    fn test_create_invite_code_admin_duplicate() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create first admin
        let result1 = create_invite_code_admin(&mut conn, "testuser", "testpass");
        assert!(result1.is_ok());

        // Try to create duplicate admin
        let result2 = create_invite_code_admin(&mut conn, "testuser", "testpass2");
        assert!(result2.is_err());

        // Verify it's a unique constraint violation
        match result2.unwrap_err() {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => {
                // This is expected
            }
            _ => panic!("Expected unique constraint violation"),
        }
    }

    #[test]
    fn test_fetch_invite_code_admin() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create an admin first
        create_invite_code_admin(&mut conn, "testuser", "testpass")
            .expect("Failed to create admin");

        // Fetch the admin
        let admin = fetch_invite_code_admin(&mut conn, "testuser");

        assert!(admin.is_some());
        let admin = admin.unwrap();
        assert_eq!(admin.username, "testuser");
        assert_eq!(admin.otp_enabled, 0);
        assert_eq!(admin.otp_verified, 0);
    }

    #[test]
    fn test_fetch_invite_code_admin_not_found() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        let admin = fetch_invite_code_admin(&mut conn, "nonexistent");
        assert!(admin.is_none());
    }

    #[test]
    fn test_fetch_invite_code_admin_login_success() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create an admin first
        create_invite_code_admin(&mut conn, "testuser", "testpass")
            .expect("Failed to create admin");

        // Test successful login
        let admin = fetch_invite_code_admin_login(&mut conn, "testuser", "testpass");

        assert!(admin.is_some());
        let admin = admin.unwrap();
        assert_eq!(admin.username, "testuser");
    }

    #[test]
    fn test_fetch_invite_code_admin_login_wrong_password() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create an admin first
        create_invite_code_admin(&mut conn, "testuser", "testpass")
            .expect("Failed to create admin");

        // Test login with wrong password
        let admin = fetch_invite_code_admin_login(&mut conn, "testuser", "wrongpass");

        assert!(admin.is_none());
    }

    #[test]
    fn test_fetch_invite_code_admin_login_nonexistent_user() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Test login with nonexistent user
        let admin = fetch_invite_code_admin_login(&mut conn, "nonexistent", "anypass");

        assert!(admin.is_none());
    }

    #[test]
    fn test_delete_invite_code_admin_success() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create an admin first
        create_invite_code_admin(&mut conn, "testuser", "testpass")
            .expect("Failed to create admin");

        // Verify admin exists
        let admin = fetch_invite_code_admin(&mut conn, "testuser");
        assert!(admin.is_some());

        // Delete the admin
        let result = delete_invite_code_admin(&mut conn, "testuser");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Should delete 1 row

        // Verify admin no longer exists
        let admin = fetch_invite_code_admin(&mut conn, "testuser");
        assert!(admin.is_none());
    }

    #[test]
    fn test_delete_invite_code_admin_not_found() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Try to delete nonexistent admin
        let result = delete_invite_code_admin(&mut conn, "nonexistent");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // Should delete 0 rows
    }

    #[test]
    fn test_password_hashing() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create an admin
        create_invite_code_admin(&mut conn, "testuser", "testpass")
            .expect("Failed to create admin");

        // Fetch the admin and verify password is hashed
        let admin = fetch_invite_code_admin(&mut conn, "testuser").expect("Admin should exist");

        // Password should be hashed, not plain text
        assert_ne!(admin.password, "testpass");
        assert!(admin.password.starts_with("$argon2")); // Argon2 hash format
    }

    #[test]
    fn test_admin_creation_validation() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Test creating admin with empty username should fail
        // Note: This test depends on validation in the route handlers
        // The helper function itself doesn't validate empty strings
        let result = create_invite_code_admin(&mut conn, "", "testpass");
        // The database will accept empty string, so this will succeed at DB level
        assert!(result.is_ok());

        // Clean up
        let _ = delete_invite_code_admin(&mut conn, "");
    }

    #[test]
    fn test_multiple_admin_operations() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create multiple admins
        let users = vec![
            ("admin1", "pass1"),
            ("admin2", "pass2"),
            ("admin3", "pass3"),
        ];

        for (username, password) in &users {
            let result = create_invite_code_admin(&mut conn, username, password);
            assert!(result.is_ok());
        }

        // Verify all admins exist
        for (username, _) in &users {
            let admin = fetch_invite_code_admin(&mut conn, username);
            assert!(admin.is_some());
        }

        // Delete one admin
        let result = delete_invite_code_admin(&mut conn, "admin2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Verify admin2 is deleted but others remain
        assert!(fetch_invite_code_admin(&mut conn, "admin1").is_some());
        assert!(fetch_invite_code_admin(&mut conn, "admin2").is_none());
        assert!(fetch_invite_code_admin(&mut conn, "admin3").is_some());
    }

    #[test]
    fn test_admin_login_integration() {
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Create admin
        create_invite_code_admin(&mut conn, "integrationtest", "mypassword")
            .expect("Failed to create admin");

        // Test successful login
        let login_result =
            fetch_invite_code_admin_login(&mut conn, "integrationtest", "mypassword");
        assert!(login_result.is_some());

        // Test failed login with wrong password
        let failed_result =
            fetch_invite_code_admin_login(&mut conn, "integrationtest", "wrongpassword");
        assert!(failed_result.is_none());

        // Test login with wrong username
        let no_user_result = fetch_invite_code_admin_login(&mut conn, "wronguser", "mypassword");
        assert!(no_user_result.is_none());
    }

    #[test]
    fn test_list_admins() {
        use crate::schema::invite_code_admin::dsl::invite_code_admin;
        use crate::user::InviteCodeAdmin;
        use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
        let pool = setup_test_db();
        let mut conn = pool.get().expect("Failed to get connection");

        // Initially no admins or only what setup_test_db might have (it seems to be clean)
        let initial_results = invite_code_admin
            .select(InviteCodeAdmin::as_select())
            .load::<InviteCodeAdmin>(&mut conn)
            .expect("DB Exception");
        let initial_count = initial_results.len();

        // Create some admins
        create_invite_code_admin(&mut conn, "list_admin1", "pass1")
            .expect("Failed to create admin");
        create_invite_code_admin(&mut conn, "list_admin2", "pass2")
            .expect("Failed to create admin");

        // List admins
        let results = invite_code_admin
            .select(InviteCodeAdmin::as_select())
            .load::<InviteCodeAdmin>(&mut conn)
            .expect("DB Exception");

        assert_eq!(results.len(), initial_count + 2);
        assert!(results.iter().any(|u| u.username == "list_admin1"));
        assert!(results.iter().any(|u| u.username == "list_admin2"));
    }
}
