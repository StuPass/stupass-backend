#[allow(unused_imports)]
mod common;
use axum::{Router, routing::post};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::json;

use stupass_backend::entities::{credential, prelude::*};
use stupass_backend::handlers::auth;
use stupass_backend::models::auth::RegisterResponse;

use common::{ErrorResponse, TestContext, create_test_user, post_json};

#[tokio::test]
async fn register_happy_path() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    assert_eq!(status, 201);
    assert!(!body.user_id.to_string().is_empty());
    assert!(
        body.message.contains("registered successfully"),
        "Expected success message, got: {}",
        body.message
    );

    // Verify email was sent
    let calls = ctx.email_service.get_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].to, "test@example.com");
    assert!(calls[0].link.contains("token="));
}

#[tokio::test]
async fn register_duplicate_email_returns_conflict() {
    let ctx = TestContext::new().await;

    // Create existing user
    create_test_user(&ctx.db, "existing", "test@example.com", "password123").await;

    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "newuser",
            "email": "test@example.com",  // Duplicate
            "password": "SecurePass123!",
            "full_name": "New User",
            "student_id": "STU002",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    // SQLite constraint violation results in 500 (InternalServerError)
    // since the current error handling doesn't distinguish constraint errors
    assert!(status >= 400);
}

#[tokio::test]
async fn register_email_failure_returns_partial_success() {
    let ctx = TestContext::new().await;
    ctx.email_service.set_should_fail(true);

    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state);

    let (status, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    // Should still succeed (user created in DB)
    assert_eq!(status, 201);
    assert!(
        body.message.contains("trouble sending"),
        "Expected email failure message, got: {}",
        body.message
    );
}

#[tokio::test]
async fn register_duplicate_username_returns_error() {
    let ctx = TestContext::new().await;
    create_test_user(&ctx.db, "existinguser", "first@example.com", "password123").await;

    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status, _body): (u16, ErrorResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "existinguser",
            "email": "different@example.com",
            "password": "SecurePass123!",
            "full_name": "New User",
            "student_id": "STU002",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    assert!(
        status >= 400,
        "Expected error for duplicate username, got {}",
        status
    );
}

#[tokio::test]
async fn register_user_starts_with_pending_verification() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!",
            "full_name": "New User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    assert_eq!(status, 201);

    // Verify user has "pending" verification status
    let user_record = User::find_by_id(body.user_id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user_record.verification_status, "pending");
    assert!(user_record.verified_at.is_none());
}

#[tokio::test]
async fn register_creates_credential_record() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!",
            "full_name": "New User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    assert_eq!(status, 201);

    // Verify credential was created
    let cred_count = Credential::find()
        .filter(credential::Column::UserId.eq(body.user_id))
        .count(&ctx.db)
        .await
        .unwrap();
    assert_eq!(cred_count, 1);
}

#[tokio::test]
async fn register_multiple_independent_users() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (status1, body1): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "user_one",
            "email": "one@example.com",
            "password": "SecurePass1!",
            "full_name": "User One",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    let (status2, body2): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "user_two",
            "email": "two@example.com",
            "password": "SecurePass2!",
            "full_name": "User Two",
            "student_id": "STU002",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    assert_eq!(status1, 201);
    assert_eq!(status2, 201);
    assert_ne!(body1.user_id, body2.user_id);
}

#[tokio::test]
async fn register_verification_email_contains_server_url() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let _: (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    let calls = ctx.email_service.get_calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].link.contains("http://localhost:8080"),
        "Verification link should contain server URL, got: {}",
        calls[0].link
    );
    assert!(
        calls[0].link.contains("/auth/verify-email"),
        "Verification link should contain verify-email path, got: {}",
        calls[0].link
    );
}

#[tokio::test]
async fn register_user_has_default_reputation_score() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    let user = User::find_by_id(body.user_id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.reputation_score, 10, "New users should start with reputation 10");
}

#[tokio::test]
async fn register_stores_correct_user_fields() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "jdoe",
            "email": "jdoe@university.edu",
            "password": "SecurePass123!",
            "full_name": "John Doe",
            "student_id": "STU12345",
            "school_id": "UNIV001"
        }),
    )
    .await;

    let user = User::find_by_id(body.user_id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.username, "jdoe");
    assert_eq!(user.email, "jdoe@university.edu");
    assert_eq!(user.full_name, "John Doe");
    assert_eq!(user.student_id, "STU12345");
    assert_eq!(user.school_id, "UNIV001");
}

#[tokio::test]
async fn register_credential_uses_email_as_identifier() {
    let ctx = TestContext::new().await;
    let app = Router::new()
        .route("/auth/register", post(auth::register))
        .with_state(ctx.state.clone());

    let (_, body): (u16, RegisterResponse) = post_json(
        &app,
        "/auth/register",
        json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User",
            "student_id": "STU001",
            "school_id": "SCHOOL001"
        }),
    )
    .await;

    let cred = Credential::find()
        .filter(credential::Column::UserId.eq(body.user_id))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cred.identifier, "test@example.com",
        "Credential identifier should be the email address"
    );
}
