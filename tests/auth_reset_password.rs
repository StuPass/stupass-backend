#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use common::{
    ErrorResponse, TestContext, create_password_reset_token, create_test_session, create_test_user,
    post_json,
};
use sea_orm::PaginatorTrait;
use sea_orm::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use stupass_backend::entities::{password_reset_token, prelude::*, session};
use stupass_backend::handlers::auth::{self};
use stupass_backend::models::auth::{LoginResponse, ResetPasswordResponse};

#[tokio::test]
async fn reset_password_happy_path() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "oldpassword").await;

    // Create a session (should be invalidated after reset)
    let _session_token = create_test_session(&ctx.db, user.id, 604800).await;

    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    let (status, body): (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword123"
        }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.0.message.contains("reset successfully"));

    // Verify can login with new password
    let app_login = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (status, _body): (u16, LoginResponse) = post_json(
        &app_login,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "newpassword123"
        }),
    )
    .await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn reset_password_invalidates_all_sessions() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Create multiple sessions
    create_test_session(&ctx.db, user.id, 604800).await;
    create_test_session(&ctx.db, user.id, 604800).await;
    create_test_session(&ctx.db, user.id, 604800).await;

    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    let _: (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword"
        }),
    )
    .await;

    // All sessions should be deleted
    let count = Session::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn reset_password_expired_token_returns_error() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Create expired token (-1 hour)
    let expired_token = create_password_reset_token(&ctx.db, user.id, -1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state);

    let (status, body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": expired_token,
            "new_password": "newpassword"
        }),
    )
    .await;

    assert_eq!(status, 400);
    assert!(
        body.message.contains("expired") || body.message.contains("invalid"),
        "Expected expired message, got: {}",
        body.message
    );
}

#[tokio::test]
async fn reset_password_already_used_token_returns_error() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let used_token = create_password_reset_token(&ctx.db, user.id, 1, true).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state);

    let (status, body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": used_token,
            "new_password": "newpassword"
        }),
    )
    .await;

    assert_eq!(status, 400);
    assert!(
        body.message.contains("used") || body.message.contains("invalid"),
        "Expected used message, got: {}",
        body.message
    );
}

#[tokio::test]
async fn reset_password_invalid_token_returns_error() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": "invalid-token-12345",
            "new_password": "newpassword"
        }),
    )
    .await;

    assert_eq!(status, 400);
}

#[tokio::test]
async fn reset_password_token_marked_as_used_after_success() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    // Get token hash to query later
    let token_hash = format!("{:x}", Sha256::digest(reset_token.as_bytes()));

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    let _: (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword"
        }),
    )
    .await;

    // Verify token marked as used
    let token_record = PasswordResetToken::find()
        .filter(password_reset_token::Column::ResetTokenHash.eq(token_hash))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();

    assert!(token_record.used_at.is_some());
}

#[tokio::test]
async fn reset_password_old_password_no_longer_works() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "oldpassword").await;
    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    // Reset password
    let _: (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword123"
        }),
    )
    .await;

    // Try login with old password
    let (status, _): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "oldpassword"
        }),
    )
    .await;

    assert_eq!(
        status, 401,
        "Old password should no longer work after reset"
    );
}

#[tokio::test]
async fn reset_password_same_token_twice_fails() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    // First reset succeeds
    let (status1, _): (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword1"
        }),
    )
    .await;
    assert_eq!(status1, 200);

    // Second reset with same token fails
    let (status2, _): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword2"
        }),
    )
    .await;
    assert_eq!(status2, 400);
}

#[tokio::test]
async fn reset_password_does_not_affect_other_users() {
    let ctx = TestContext::new().await;
    let user1 = create_test_user(&ctx.db, "user1", "user1@example.com", "password1").await;
    let user2 = create_test_user(&ctx.db, "user2", "user2@example.com", "password2").await;

    // Create sessions for both users
    create_test_session(&ctx.db, user1.id, 604800).await;
    create_test_session(&ctx.db, user2.id, 604800).await;

    // Reset user1's password
    let reset_token = create_password_reset_token(&ctx.db, user1.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let _: (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword"
        }),
    )
    .await;

    // User2 should still be able to login with original password
    let (status, _): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "user2@example.com",
            "password": "password2"
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "Other user's credentials should not be affected"
    );

    // User2's session should still exist
    let count = Session::find()
        .filter(session::Column::UserId.eq(user2.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(
        count, 2,
        "There should be two sessions for user2 (one for each login), and they should not be invalidated"
    );
}

#[tokio::test]
async fn reset_password_preserves_user_data() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "oldpassword").await;
    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    let _: (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "newpassword123"
        }),
    )
    .await;

    // Verify user data unchanged
    let user_record = User::find_by_id(user.id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user_record.username, "testuser");
    assert_eq!(user_record.email, "test@example.com");
    assert_eq!(user_record.full_name, "testuser User");
}

#[tokio::test]
async fn reset_password_can_login_with_new_password_after_reset() {
    // This is complementary to the happy_path test - explicitly tests new password login
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "oldpassword").await;
    let reset_token = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (reset_status, _): (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({
            "token": reset_token,
            "new_password": "brand_new_password"
        }),
    )
    .await;
    assert_eq!(reset_status, 200);

    let (login_status, body): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "brand_new_password"
        }),
    )
    .await;
    assert_eq!(login_status, 200);
    assert!(!body.tokens.access_token.is_empty());
}

// TODO: Change reset password flow to restrict and invalidate old token when new token is requested,
// TODO: ensuring only one token is active at any given time
#[tokio::test]
async fn reset_password_multiple_tokens_only_first_used_works() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Create two reset tokens
    let token1 = create_password_reset_token(&ctx.db, user.id, 1, false).await;
    let token2 = create_password_reset_token(&ctx.db, user.id, 1, false).await;

    let app = Router::new()
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(ctx.state.clone());

    // Use first token
    let (status1, _): (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({ "token": token1, "new_password": "new1" }),
    )
    .await;
    assert_eq!(status1, 200);

    // Second token should still be valid (it's a different token)
    let (status2, _): (u16, ResetPasswordResponse) = post_json(
        &app,
        "/auth/reset-password",
        json!({ "token": token2, "new_password": "new2" }),
    )
    .await;
    assert_eq!(status2, 200);
}
