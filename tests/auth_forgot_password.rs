#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use common::{TestContext, create_test_user, post_json};
use sea_orm::PaginatorTrait;
use sea_orm::prelude::*;
use serde_json::json;
use stupass_backend::entities::{password_reset_token, prelude::*};
use stupass_backend::handlers::auth;
use stupass_backend::models::auth::ForgotPasswordResponse;

#[tokio::test]
async fn forgot_password_existing_user_returns_success() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let (status, body): (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(
        body.0.message.contains("If an account"),
        "Expected generic success message, got: {}",
        body.0.message
    );
}

#[tokio::test]
async fn forgot_password_nonexistent_email_returns_success() {
    // Anti-enumeration: should return the same success message for non-existent emails
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let (status, body): (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "nonexistent@example.com" }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(
        body.0.message.contains("If an account"),
        "Expected generic success message to prevent email enumeration, got: {}",
        body.0.message
    );
}

#[tokio::test]
async fn forgot_password_creates_reset_token_in_db() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    // Verify a reset token was created for this user
    let token_count = PasswordResetToken::find()
        .filter(password_reset_token::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(token_count, 1);
}

#[tokio::test]
async fn forgot_password_no_token_created_for_nonexistent_email() {
    let ctx = TestContext::new().await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "nonexistent@example.com" }),
    )
    .await;

    // No reset token should have been created
    let token_count = PasswordResetToken::find().count(&ctx.db).await.unwrap();
    assert_eq!(token_count, 0);
}

#[tokio::test]
async fn forgot_password_rate_limiting_after_three_requests() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    // First 3 requests should succeed normally
    for _ in 0..3 {
        let (status, _): (u16, ForgotPasswordResponse) = post_json(
            &app,
            "/auth/forgot-password",
            json!({ "email": "test@example.com" }),
        )
        .await;
        assert_eq!(status, 200);
    }

    // 4th request should still return 200 but with rate limit message
    let (status, body): (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(
        body.0.message.contains("Too many requests"),
        "Expected rate limit message, got: {}",
        body.0.message
    );
}

#[tokio::test]
async fn forgot_password_sends_email_with_reset_link() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    let calls = ctx.email_service.get_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].to, "test@example.com");
    assert!(
        calls[0].link.contains("reset-password"),
        "Reset link should contain 'reset-password', got: {}",
        calls[0].link
    );
    assert!(
        calls[0].link.contains("token="),
        "Reset link should contain token parameter, got: {}",
        calls[0].link
    );
}

#[tokio::test]
async fn forgot_password_nonexistent_email_does_not_send_email() {
    let ctx = TestContext::new().await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "nonexistent@example.com" }),
    )
    .await;

    let calls = ctx.email_service.get_calls();
    assert_eq!(
        calls.len(),
        0,
        "Should not send email for non-existent user"
    );
}

#[tokio::test]
async fn forgot_password_multiple_requests_create_multiple_tokens() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    // Send 3 requests (within rate limit)
    for _ in 0..3 {
        let _: (u16, ForgotPasswordResponse) = post_json(
            &app,
            "/auth/forgot-password",
            json!({ "email": "test@example.com" }),
        )
        .await;
    }

    // Should have 3 tokens in DB
    let token_count = PasswordResetToken::find()
        .filter(password_reset_token::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(token_count, 3);
}

#[tokio::test]
async fn forgot_password_rate_limited_request_does_not_create_token() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    // Exhaust rate limit (3 requests)
    for _ in 0..3 {
        let _: (u16, ForgotPasswordResponse) = post_json(
            &app,
            "/auth/forgot-password",
            json!({ "email": "test@example.com" }),
        )
        .await;
    }

    // 4th request (rate limited) should NOT create a new token
    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    let token_count = PasswordResetToken::find()
        .filter(password_reset_token::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(
        token_count, 3,
        "Rate-limited request should not create additional tokens"
    );
}

#[tokio::test]
async fn forgot_password_reset_link_contains_fe_url() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/forgot-password", post(auth::forgot_password))
        .with_state(ctx.state.clone());

    let _: (u16, ForgotPasswordResponse) = post_json(
        &app,
        "/auth/forgot-password",
        json!({ "email": "test@example.com" }),
    )
    .await;

    let calls = ctx.email_service.get_calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].link.contains("http://localhost:3000"),
        "Reset link should contain frontend URL, got: {}",
        calls[0].link
    );
}
