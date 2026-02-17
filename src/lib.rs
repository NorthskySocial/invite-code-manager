extern crate alloc;
extern crate core;

pub mod apis;
pub mod auth;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod schema;
pub mod state;
pub mod user;

use alloc::string::String;
use deadpool_diesel::sqlite::Pool;
use utoipa::ToSchema;

#[derive(Clone)]
pub struct DbConn(pub Pool);

pub type DBPool = DbConn;

pub type DBPooledConnection = diesel::SqliteConnection;

// Shared structures that are used across modules
#[derive(serde::Deserialize, Debug, serde::Serialize, ToSchema)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

// Constants used by apis
pub const GET_INVITE_CODES: &str = "/xrpc/com.atproto.admin.getInviteCodes";
pub const DISABLE_INVITE_CODES: &str = "/xrpc/com.atproto.admin.disableInviteCodes";
pub const CREATE_INVITE_CODES: &str = "/xrpc/com.atproto.server.createInviteCodes";
pub const GET_ACCOUNT_INFOS: &str = "/xrpc/com.atproto.admin.getAccountInfos";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        create_invite_code_admin, delete_invite_code_admin, fetch_invite_code_admin,
        fetch_invite_code_admin_login,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use core::{assert, assert_eq, assert_ne};
    use deadpool_diesel::sqlite::{Manager, Pool};
    use diesel::RunQueryDsl;

    async fn setup_test_db() -> Pool {
        let manager = Manager::new(":memory:", deadpool_diesel::Runtime::Tokio1);
        let pool = Pool::builder(manager)
            .build()
            .expect("Failed to create test pool");

        // Run migrations on the test database
        let conn = pool.get().await.expect("Failed to get connection");
        conn.interact(|conn| {
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
            .execute(conn)
        })
        .await
        .expect("Interact error")
        .expect("Failed to create test table");

        pool
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

    #[tokio::test]
    async fn test_create_invite_code_admin_success() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        let result = create_invite_code_admin(&db_conn, "testuser", "testpass").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_create_invite_code_admin_duplicate() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create the first admin
        let result1 = create_invite_code_admin(&db_conn, "testuser", "testpass").await;
        assert!(result1.is_ok());

        // Try to create a duplicate admin
        let result2 = create_invite_code_admin(&db_conn, "testuser", "testpass2").await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_fetch_invite_code_admin() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create an admin first
        create_invite_code_admin(&db_conn, "testuser", "testpass")
            .await
            .expect("Failed to create admin");

        // Fetch the admin
        let admin = fetch_invite_code_admin(&db_conn, "testuser").await;

        assert!(admin.is_some());
        let admin = admin.unwrap();
        assert_eq!(admin.username, "testuser");
        assert_eq!(admin.otp_enabled, 0);
        assert_eq!(admin.otp_verified, 0);
    }

    #[tokio::test]
    async fn test_fetch_invite_code_admin_not_found() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        let admin = fetch_invite_code_admin(&db_conn, "nonexistent").await;
        assert!(admin.is_none());
    }

    #[tokio::test]
    async fn test_fetch_invite_code_admin_login_success() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create an admin first
        create_invite_code_admin(&db_conn, "testuser", "testpass")
            .await
            .expect("Failed to create admin");

        // Test a successful login
        let admin = fetch_invite_code_admin_login(&db_conn, "testuser", "testpass").await;

        assert!(admin.is_some());
        let admin = admin.unwrap();
        assert_eq!(admin.username, "testuser");
    }

    #[tokio::test]
    async fn test_fetch_invite_code_admin_login_wrong_password() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create an admin first
        create_invite_code_admin(&db_conn, "testuser", "testpass")
            .await
            .expect("Failed to create admin");

        // Test login with the wrong password
        let admin = fetch_invite_code_admin_login(&db_conn, "testuser", "wrongpass").await;

        assert!(admin.is_none());
    }

    #[tokio::test]
    async fn test_fetch_invite_code_admin_login_nonexistent_user() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Test login with a nonexistent user
        let admin = fetch_invite_code_admin_login(&db_conn, "nonexistent", "anypass").await;

        assert!(admin.is_none());
    }

    #[tokio::test]
    async fn test_delete_invite_code_admin_success() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create an admin first
        create_invite_code_admin(&db_conn, "testuser", "testpass")
            .await
            .expect("Failed to create admin");

        // Verify that admin exists
        let admin = fetch_invite_code_admin(&db_conn, "testuser").await;
        assert!(admin.is_some());

        // Delete the admin
        let result = delete_invite_code_admin(&db_conn, "testuser").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Verify admin no longer exists
        let admin = fetch_invite_code_admin(&db_conn, "testuser").await;
        assert!(admin.is_none());
    }

    #[tokio::test]
    async fn test_delete_invite_code_admin_not_found() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Try to delete a nonexistent admin
        let result = delete_invite_code_admin(&db_conn, "nonexistent").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_password_hashing() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create an admin
        create_invite_code_admin(&db_conn, "testuser", "testpass")
            .await
            .expect("Failed to create admin");

        // Fetch the admin and verify the password is hashed
        let admin = fetch_invite_code_admin(&db_conn, "testuser")
            .await
            .expect("Admin should exist");

        // Password should be hashed, not plain text
        assert_ne!(admin.password, "testpass");
        assert!(admin.password.starts_with("$argon2")); // Argon2 hash format
    }

    #[tokio::test]
    async fn test_admin_creation_validation() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Test creating admin with empty username should fail
        // Note: This test depends on validation in the route handlers
        // The helper function itself doesn't validate empty strings
        let result = create_invite_code_admin(&db_conn, "", "testpass").await;
        // The database will accept empty string, so this will succeed at DB level
        assert!(result.is_ok());

        // Clean up
        let _ = delete_invite_code_admin(&db_conn, "").await;
    }

    #[tokio::test]
    async fn test_multiple_admin_operations() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create multiple admins
        let users = vec![
            ("admin1", "pass1"),
            ("admin2", "pass2"),
            ("admin3", "pass3"),
        ];

        for (username, password) in &users {
            let result = create_invite_code_admin(&db_conn, username, password).await;
            assert!(result.is_ok());
        }

        // Verify that all admins exist
        for (username, _) in &users {
            let admin = fetch_invite_code_admin(&db_conn, username).await;
            assert!(admin.is_some());
        }

        // Delete one admin
        let result = delete_invite_code_admin(&db_conn, "admin2").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Verify admin2 is deleted but the others remain
        assert!(fetch_invite_code_admin(&db_conn, "admin1").await.is_some());
        assert!(fetch_invite_code_admin(&db_conn, "admin2").await.is_none());
        assert!(fetch_invite_code_admin(&db_conn, "admin3").await.is_some());
    }

    #[tokio::test]
    async fn test_admin_login_integration() {
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create admin
        create_invite_code_admin(&db_conn, "integrationtest", "mypassword")
            .await
            .expect("Failed to create admin");

        // Test successful login
        let login_result =
            fetch_invite_code_admin_login(&db_conn, "integrationtest", "mypassword").await;
        assert!(login_result.is_some());

        // Test failed login with the wrong password
        let failed_result =
            fetch_invite_code_admin_login(&db_conn, "integrationtest", "wrongpassword").await;
        assert!(failed_result.is_none());

        // Test login with the wrong username
        let no_user_result =
            fetch_invite_code_admin_login(&db_conn, "wronguser", "mypassword").await;
        assert!(no_user_result.is_none());
    }

    #[tokio::test]
    async fn test_list_admins() {
        use crate::schema::invite_code_admin::dsl::invite_code_admin;
        use crate::user::InviteCodeAdmin;
        use diesel::{QueryDsl, SelectableHelper};
        let pool = setup_test_db().await;
        let db_conn = DbConn(pool);

        // Create some admins
        create_invite_code_admin(&db_conn, "list_admin1", "pass1")
            .await
            .expect("Failed to create admin");
        create_invite_code_admin(&db_conn, "list_admin2", "pass2")
            .await
            .expect("Failed to create admin");

        // List admins
        let conn = db_conn.0.get().await.expect("Failed to get connection");
        let results = conn
            .interact(|conn| {
                invite_code_admin
                    .select(InviteCodeAdmin::as_select())
                    .load::<InviteCodeAdmin>(conn)
                    .expect("DB Exception")
            })
            .await
            .expect("Interact error");

        assert!(results.len() >= 2);
        assert!(results.iter().any(|u| u.username == "list_admin1"));
        assert!(results.iter().any(|u| u.username == "list_admin2"));
    }
}
