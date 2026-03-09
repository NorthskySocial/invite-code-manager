use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
mod common;

#[tokio::test]
async fn test_get_account_email_unauthorized() {
    let db_pool = common::setup_test_db();
    common::init_db(&db_pool).await;
    let app = common::setup_app(db_pool).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/account/email?did=did:plc:123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be 401 Unauthorized because we didn't provide a session
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
