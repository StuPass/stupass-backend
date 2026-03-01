#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use common::{ErrorResponse, TestContext, create_test_session, create_test_user, post_json};
use sea_orm::prelude::*;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait};
use serde_json::json;
use stupass_backend::entities::session;
use stupass_backend::handlers::auth::{self};
use stupass_backend::models::auth::RefreshResponse;

#[tokio::test]
async fn refresh_happy_path() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let old_refresh_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state);

    let (status, body): (u16, RefreshResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": old_refresh_token }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(!body.tokens.access_token.is_empty());
    assert!(!body.tokens.refresh_token.is_empty());

    // Old token should be invalidated (rotated) - new token is different
    assert_ne!(body.tokens.refresh_token, old_refresh_token);
}

#[tokio::test]
async fn refresh_expired_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    // Create expired session (-1 hour from now)
    let expired_token = create_test_session(&ctx.db, user.id, -3600).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": expired_token }),
    )
    .await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn refresh_invalid_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": "invalid-token" }),
    )
    .await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn refresh_token_rotation_invalidates_old() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let old_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    // First refresh
    let (_, body1): (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": old_token })).await;

    // Try to use old token again (should fail - token rotation)
    let (status, _body): (u16, ErrorResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": old_token })).await;

    assert_eq!(status, 401);

    // New token should work
    let (status, _body): (u16, RefreshResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": body1.tokens.refresh_token }),
    )
    .await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn refresh_session_count_remains_same() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let token = create_test_session(&ctx.db, user.id, 604800).await;

    let count_before = session::Entity::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    let _: (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": token })).await;

    let count_after = session::Entity::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();

    assert_eq!(
        count_before, count_after,
        "Refresh should not create new sessions"
    );
}

#[tokio::test]
async fn refresh_does_not_affect_other_sessions() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let token1 = create_test_session(&ctx.db, user.id, 604800).await;
    let token2 = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    // Refresh first session
    let _: (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": token1 })).await;

    // Second session should still be usable
    let (status, _): (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": token2 })).await;

    assert_eq!(status, 200);
}

#[tokio::test]
async fn refresh_new_tokens_differ_from_old() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let old_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": old_token })).await;

    assert_ne!(body.tokens.refresh_token, old_token);
    assert!(!body.tokens.access_token.is_empty());
    assert!(!body.tokens.refresh_token.is_empty());
}

#[tokio::test]
async fn refresh_empty_string_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state);

    let (status, _): (u16, ErrorResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": "" })).await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn refresh_preserves_correct_expiry_in_response() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": token })).await;

    assert_eq!(
        body.tokens.expires_in, 3600,
        "expires_in should match JWT access token expiry"
    );
}

#[tokio::test]
async fn refresh_chain_three_rotations() {
    // Test that we can chain multiple refreshes consecutively
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let initial_token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    // First refresh
    let (s1, b1): (u16, RefreshResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": initial_token }),
    )
    .await;
    assert_eq!(s1, 200);

    // Second refresh
    let (s2, b2): (u16, RefreshResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": b1.tokens.refresh_token }),
    )
    .await;
    assert_eq!(s2, 200);

    // Third refresh
    let (s3, _b3): (u16, RefreshResponse) = post_json(
        &app,
        "/auth/refresh",
        json!({ "refresh_token": b2.tokens.refresh_token }),
    )
    .await;
    assert_eq!(s3, 200);
}

#[tokio::test]
async fn refresh_access_token_is_valid_jwt() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;
    let token = create_test_session(&ctx.db, user.id, 604800).await;

    let app = Router::new()
        .route("/auth/refresh", post(auth::refresh))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RefreshResponse) =
        post_json(&app, "/auth/refresh", json!({ "refresh_token": token })).await;

    let parts: Vec<&str> = body.tokens.access_token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "Refreshed access token should be a valid JWT (3 parts)"
    );
}
