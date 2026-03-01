#![allow(unused)]

mod common;
use axum::{Router, routing::get};
use common::{
    TestContext, create_unverified_test_user, create_verified_test_user,
    generate_email_verify_token, generate_wrong_purpose_token, get_raw,
};
use sea_orm::EntityTrait;
use sea_orm::prelude::*;
use stupass_backend::entities::prelude::*;
use stupass_backend::handlers::auth;
use uuid::Uuid;

#[tokio::test]
async fn verify_email_success() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Email Verified"),
        "Expected success HTML, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_updates_user_status_in_db() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let _ = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    // Verify user status updated in DB
    let updated_user = User::find_by_id(user.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.verification_status, "verified");
    assert!(updated_user.verified_at.is_some());
}

#[tokio::test]
async fn verify_email_already_verified() {
    let ctx = TestContext::new().await;
    let user = create_verified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Already Verified"),
        "Expected already verified HTML, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_invalid_token() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, "/auth/verify-email?token=invalid-garbage-token").await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Verification Failed"),
        "Expected failure HTML for invalid token, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_expired_token() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Generate a token that expired 2 hours ago
    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", -2);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Verification Failed"),
        "Expected failure HTML for expired token, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_wrong_purpose_token() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let token = generate_wrong_purpose_token(user.id, "test-secret-key-for-testing-only");

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Invalid Link"),
        "Expected invalid link HTML for wrong purpose, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_nonexistent_user() {
    let ctx = TestContext::new().await;
    let fake_user_id = Uuid::new_v4();

    let token = generate_email_verify_token(fake_user_id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("User Not Found"),
        "Expected user not found HTML, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_wrong_secret_token() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Generate token with wrong secret
    let token = generate_email_verify_token(user.id, "wrong-secret-key", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let (status, body) = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    assert_eq!(status, 200);
    assert!(
        body.contains("Verification Failed"),
        "Expected failure HTML for wrong secret, got: {}",
        body
    );
}

#[tokio::test]
async fn verify_email_does_not_change_already_verified_user() {
    let ctx = TestContext::new().await;
    let user = create_verified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Record the original verified_at
    let original_user = User::find_by_id(user.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let original_verified_at = original_user.verified_at;

    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let _ = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    // verified_at should not change
    let updated_user = User::find_by_id(user.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.verified_at, original_verified_at);
}

#[tokio::test]
async fn verify_email_user_data_preserved_after_verification() {
    let ctx = TestContext::new().await;
    let user =
        create_unverified_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let token = generate_email_verify_token(user.id, "test-secret-key-for-testing-only", 24);

    let app = Router::new()
        .route("/auth/verify-email", get(auth::verify_email))
        .with_state(ctx.state.clone());

    let _ = get_raw(&app, &format!("/auth/verify-email?token={}", token)).await;

    // Verify user data is preserved
    let updated_user = User::find_by_id(user.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.username, "testuser");
    assert_eq!(updated_user.email, "test@example.com");
    assert_eq!(updated_user.full_name, "testuser User");
}
