#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use common::{ErrorResponse, TestContext, create_test_user, post_json};
use sea_orm::prelude::*;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait};
use serde_json::json;
use stupass_backend::entities::session;
use stupass_backend::handlers::auth::{self};
use stupass_backend::models::auth::{LoginResponse, RegisterResponse};

#[tokio::test]
async fn login_with_email() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "correctpassword").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (status, body): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "correctpassword"
        }),
    )
    .await;

    assert_eq!(status, 200);
    assert!(body.tokens.access_token.len() > 0);
    assert!(body.tokens.refresh_token.len() > 0);
    assert_eq!(body.tokens.expires_in, 3600);

    // Verify session created in DB
    let session_count = session::Entity::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(session_count, 1);
}

#[tokio::test]
async fn login_invalid_password_returns_unauthorized() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "correctpassword").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "wrongpassword"
        }),
    )
    .await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn login_nonexistent_user_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "nonexistent@example.com",
            "password": "anypassword"
        }),
    )
    .await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn login_creates_new_session_each_time() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    // Login twice
    let _: (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({"identifier": "test@example.com", "password": "password"}),
    )
    .await;

    let _: (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({"identifier": "test@example.com", "password": "password"}),
    )
    .await;

    // Should have 2 sessions
    let count = session::Entity::find()
        .filter(session::Column::UserId.eq(user.id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn login_returns_valid_jwt_access_token() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (status, body): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "password"
        }),
    )
    .await;

    assert_eq!(status, 200);
    // Verify the access token is a valid JWT (3 dot-separated parts)
    let parts: Vec<&str> = body.tokens.access_token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "JWT should have 3 parts (header.payload.signature)"
    );
}

#[tokio::test]
async fn login_empty_password_returns_unauthorized() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state);

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": ""
        }),
    )
    .await;

    assert_eq!(status, 401);
}

#[tokio::test]
async fn login_session_records_correct_user_id() {
    let ctx = TestContext::new().await;
    let user = create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let _: (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "password"
        }),
    )
    .await;

    // Verify the session's user_id matches
    let sessions: Vec<session::Model> = session::Entity::find()
        .filter(session::Column::UserId.eq(user.id))
        .all(&ctx.db)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].user_id, user.id);
}

#[tokio::test]
async fn login_different_users_get_different_tokens() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "user1", "user1@example.com", "password1").await;
    create_test_user(&ctx.db, "user2", "user2@example.com", "password2").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (_, body1): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({ "identifier": "user1@example.com", "password": "password1" }),
    )
    .await;

    let (_, body2): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({ "identifier": "user2@example.com", "password": "password2" }),
    )
    .await;

    assert_ne!(body1.tokens.access_token, body2.tokens.access_token);
    assert_ne!(body1.tokens.refresh_token, body2.tokens.refresh_token);
}

#[tokio::test]
async fn login_after_register_flow() {
    // Full flow: register then login
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    // Register
    let (reg_status, _): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "newuser",
            "email": "new@example.com",
            "password": "MyPassword123!",
            "full_name": "New User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;
    assert_eq!(reg_status, 201);

    // Login with same credentials
    let (login_status, login_body): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "new@example.com",
            "password": "MyPassword123!"
        }),
    )
    .await;
    assert_eq!(login_status, 200);
    assert!(!login_body.tokens.access_token.is_empty());
}

#[tokio::test]
async fn login_response_expires_in_matches_config() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (_, body): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({
            "identifier": "test@example.com",
            "password": "password"
        }),
    )
    .await;

    assert_eq!(
        body.tokens.expires_in, 3600,
        "expires_in should match configured access token expiry"
    );
}

#[tokio::test]
async fn login_successive_logins_produce_different_tokens() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "testuser", "test@example.com", "password").await;

    let app = Router::new()
        .route("/auth/login", post(auth::login))
        .with_state(ctx.state.clone());

    let (_, body1): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({ "identifier": "test@example.com", "password": "password" }),
    )
    .await;

    let (_, body2): (u16, LoginResponse) = post_json(
        &app,
        "/auth/login",
        json!({ "identifier": "test@example.com", "password": "password" }),
    )
    .await;

    // Each login should produce unique tokens
    assert_ne!(
        body1.tokens.refresh_token, body2.tokens.refresh_token,
        "Each login should generate a unique refresh token"
    );
}
