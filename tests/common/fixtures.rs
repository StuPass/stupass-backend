#![allow(dead_code, unused_imports)]

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngCore;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use stupass_backend::entities::{credential, password_reset_token, session, user};

/// Test user fixture
pub struct TestUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: String, // Plain text for testing
}

/// Creates a test user with credential
pub async fn create_test_user(
    db: &DatabaseConnection,
    username: &str,
    email: &str,
    password: &str,
) -> TestUser {
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    // Create user
    let user_model = user::ActiveModel {
        id: Set(user_id),
        username: Set(username.to_string()),
        email: Set(email.to_string()),
        full_name: Set(format!("{} User", username)),
        school_id: Set("TEST_SCHOOL".to_string()),
        student_id: Set(format!("STU-{}", username)),
        reputation_score: Set(10),
        verification_status: Set("verified".to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    user_model
        .insert(db)
        .await
        .expect("Failed to create test user");

    // Create credential with hashed password
    let hashed = hash_password(password);
    let credential_model = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(email.to_string()),
        secret: Set(hashed),
        provider_id: Set(1), // Password provider
        user_id: Set(user_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    credential_model
        .insert(db)
        .await
        .expect("Failed to create credential");

    TestUser {
        id: user_id,
        username: username.to_string(),
        email: email.to_string(),
        password: password.to_string(),
    }
}

/// Creates a session for a user, returns the plain refresh token
pub async fn create_test_session(
    db: &DatabaseConnection,
    user_id: Uuid,
    expires_in_seconds: i64,
) -> String {
    let refresh_token = generate_test_token();
    let token_hash = hash_token(&refresh_token);

    let now = Utc::now();
    let session_model = session::ActiveModel {
        session_token_hash: Set(token_hash),
        ip_address: Set(None),
        user_agent: Set(None),
        valid_from: Set(now),
        expires_at: Set(now + Duration::seconds(expires_in_seconds)),
        last_refresh: Set(now),
        user_id: Set(user_id),
        ..Default::default()
    };
    session_model
        .insert(db)
        .await
        .expect("Failed to create session");

    refresh_token
}

/// Creates a password reset token for a user
pub async fn create_password_reset_token(
    db: &DatabaseConnection,
    user_id: Uuid,
    expires_in_hours: i64,
    used: bool,
) -> String {
    let token = generate_test_token();
    let token_hash = hash_token(&token);

    let now = Utc::now();
    let reset_token_model = password_reset_token::ActiveModel {
        reset_token_hash: Set(token_hash),
        created_at: Set(now),
        expires_at: Set(now + Duration::hours(expires_in_hours)),
        used_at: Set(if used { Some(now) } else { None }),
        user_id: Set(user_id),
        ..Default::default()
    };
    reset_token_model
        .insert(db)
        .await
        .expect("Failed to create reset token");

    token
}

/// Hash a password using Argon2 (for test fixtures)
fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .expect("Failed to hash password")
}

/// Hash a token using SHA256
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a random test token
fn generate_test_token() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Creates a test user with "pending" verification status (unverified, no verified_at)
pub async fn create_unverified_test_user(
    db: &DatabaseConnection,
    username: &str,
    email: &str,
    password: &str,
) -> TestUser {
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    let user_model = user::ActiveModel {
        id: Set(user_id),
        username: Set(username.to_string()),
        email: Set(email.to_string()),
        full_name: Set(format!("{} User", username)),
        school_id: Set("TEST_SCHOOL".to_string()),
        student_id: Set(format!("STU-{}", username)),
        reputation_score: Set(10),
        verification_status: Set("pending".to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    user_model
        .insert(db)
        .await
        .expect("Failed to create unverified test user");

    let hashed = hash_password(password);
    let credential_model = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(email.to_string()),
        secret: Set(hashed),
        provider_id: Set(1),
        user_id: Set(user_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    credential_model
        .insert(db)
        .await
        .expect("Failed to create credential");

    TestUser {
        id: user_id,
        username: username.to_string(),
        email: email.to_string(),
        password: password.to_string(),
    }
}

/// Creates a test user that is fully verified (verified_at is set)
pub async fn create_verified_test_user(
    db: &DatabaseConnection,
    username: &str,
    email: &str,
    password: &str,
) -> TestUser {
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    let user_model = user::ActiveModel {
        id: Set(user_id),
        username: Set(username.to_string()),
        email: Set(email.to_string()),
        full_name: Set(format!("{} User", username)),
        school_id: Set("TEST_SCHOOL".to_string()),
        student_id: Set(format!("STU-{}", username)),
        reputation_score: Set(10),
        verification_status: Set("verified".to_string()),
        verified_at: Set(Some(now)),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    user_model
        .insert(db)
        .await
        .expect("Failed to create verified test user");

    let hashed = hash_password(password);
    let credential_model = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(email.to_string()),
        secret: Set(hashed),
        provider_id: Set(1),
        user_id: Set(user_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    credential_model
        .insert(db)
        .await
        .expect("Failed to create credential");

    TestUser {
        id: user_id,
        username: username.to_string(),
        email: email.to_string(),
        password: password.to_string(),
    }
}

/// Generate a valid email verification JWT token
pub fn generate_email_verify_token(user_id: Uuid, secret: &str, expires_in_hours: i64) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use stupass_backend::models::auth::EmailVerifyClaims;

    let expiration = (Utc::now() + Duration::hours(expires_in_hours)).timestamp() as usize;

    let claims = EmailVerifyClaims {
        sub: user_id,
        exp: expiration,
        purpose: String::from("email_verification"),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to generate verify email token")
}

/// Generate a JWT token with wrong purpose (for testing purpose validation)
pub fn generate_wrong_purpose_token(user_id: Uuid, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use stupass_backend::models::auth::EmailVerifyClaims;

    let expiration = (Utc::now() + Duration::hours(24)).timestamp() as usize;

    let claims = EmailVerifyClaims {
        sub: user_id,
        exp: expiration,
        purpose: String::from("password_reset"),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to generate wrong purpose token")
}
