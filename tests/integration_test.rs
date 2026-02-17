use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use invite_code_manager::LoginUser;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn test_health_check() {
    let db_pool = common::setup_test_db();
    common::init_db(&db_pool).await;
    let app = common::setup_app(db_pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn test_login_workflow() {
    let db_pool = common::setup_test_db();
    common::init_db(&db_pool).await;
    let app = common::setup_app(db_pool.clone()).await;

    // Create a test admin
    {
        let conn = db_pool.0.get().await.unwrap();
        conn.interact(|conn| {
            common::create_test_admin(conn, "admin", "password123");
        })
        .await
        .unwrap();
    }

    // Attempt login
    let login_payload = LoginUser {
        username: "admin".to_string(),
        password: "password123".to_string(),
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be CREATED (201) because OTP is not verified yet
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_login_wrong_password() {
    let db_pool = common::setup_test_db();
    common::init_db(&db_pool).await;
    let app = common::setup_app(db_pool.clone()).await;

    // Create a test admin
    {
        let conn = db_pool.0.get().await.unwrap();
        conn.interact(|conn| {
            common::create_test_admin(conn, "admin", "password123");
        })
        .await
        .unwrap();
    }

    // Attempt login with the wrong password
    let login_payload = LoginUser {
        username: "admin".to_string(),
        password: "wrongpassword".to_string(),
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
