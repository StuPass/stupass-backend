#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use common::{ErrorResponse, TestContext, create_test_session, create_test_user, post_json};
use sea_orm::PaginatorTrait;
use sea_orm::prelude::*;
use serde_json::json;
use stupass_backend::entities::{prelude::*, session};
use stupass_backend::handlers::auth::{self};
use stupass_backend::models::auth::LogoutResponse;

#[tokio::test]
async fn logout_happy_path() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let refresh_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state.clone());

    let (status, body): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": refresh_token }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.0.message.contains("logged out"));

    // Verify session deleted
    let count = Session::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn logout_invalid_token_returns_success() {
    // Note: Current implementation treats invalid token as success (idempotent)
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state);

    let (status, _body): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": "invalid-token" }),
    )
    .await;

    // Implementation returns success even for invalid tokens
    assert_eq!(status, 200);
}

#[tokio::test]
async fn logout_null_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) =
        post_json(&app, "/auth/logout", json!({ "refresh_token": null })).await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn logout_only_invalidates_target_session() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    // Create two sessions
    let token1 = create_test_session(&ctx.db, user.id, 604800).await;
    let _token2 = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state.clone());

    // Logout with first token
    let (status, _): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": token1 }),
    )
    .await;

    assert_eq!(status, 200);

    // Only one session should remain
    let count = Session::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(count, 1, "Only the target session should be deleted");
}

#[tokio::test]
async fn logout_same_token_twice_is_idempotent() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state.clone());

    // First logout
    let (status1, _): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": token }),
    )
    .await;

    // Second logout with same token
    let (status2, _): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": token }),
    )
    .await;

    assert_eq!(status1, 200);
    assert_eq!(status2, 200);
}

#[tokio::test]
async fn logout_does_not_affect_other_users_sessions() {
    let ctx = TestContext::new().await;
    let user1 = create_test_user(&ctx.db, "user1", "user1@example.com", "password1").await;
    let user2 = create_test_user(&ctx.db, "user2", "user2@example.com", "password2").await;

    let token1 = create_test_session(&ctx.db, user1.id, 604800).await;
    let _token2 = create_test_session(&ctx.db, user2.id, 604800).await;

    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state.clone());

    // Logout user1
    let _: (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": token1 }),
    )
    .await;

    // User2's session should still exist
    let count = Session::find()
        .filter(session::Column::UserId.eq(user2.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(count, 1, "Other user's session should not be affected");
}

#[tokio::test]
async fn logout_empty_string_token_returns_success() {
    // Empty string token hashes to a deterministic value, finds no match, returns success
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state);

    let (status, _): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": "" }),
    )
    .await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn logout_response_contains_success_message() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let refresh_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/logout", post(auth::logout))
        .with_state(ctx.state.clone());

    let (_, body): (u16, LogoutResponse) = post_json(
        &app,
        "/auth/logout",
        json!({ "refresh_token": refresh_token }),
    )
    .await;

    assert!(
        body.0.message.contains("logged out"),
        "Expected logged out message, got: {}",
        body.0.message
    );
}
