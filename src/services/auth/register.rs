use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, EntityTrait, Set, TransactionTrait};
use tokio::task;
use tracing::{debug, error, info};

use crate::{
    entities::{auth_provider, credential, prelude::AuthProvider, user},
    errors::AppError,
    models::auth::{EmailVerifyClaims, RegisterRequest, RegisterResponse, VerifyEmailOutcome},
    services::auth::AuthDeps,
};

pub async fn register_user<D: AuthDeps>(
    deps: &D,
    req: RegisterRequest,
) -> Result<RegisterResponse, AppError> {
    let RegisterRequest {
        username,
        email,
        password,
        full_name,
        student_id,
        school_id,
    } = req;

    info!("Starting registration process for email: {}", email);

    let password_to_hash = password.clone();

    debug!("Offloading password hashing to background thread...");

    let hashed_password = task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password hashing: {:?}", e);
        AppError::InternalServerError
    })?
    .map_err(|e| {
        error!("Failed to hash password: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Password hashed successfully. Initiating database transaction.");

    let txn = deps.db().begin().await.map_err(|e| {
        error!("Failed to begin txn: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Inserting User record...");

    let now = Utc::now();

    let new_user = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        username: Set(username.clone()),
        email: Set(email.clone()),
        full_name: Set(full_name),
        school_id: Set(school_id),
        student_id: Set(student_id),
        reputation_score: Set(10),
        verification_status: Set(String::from("pending")),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let inserted_user = new_user.insert(&txn).await.map_err(|e| {
        error!("Failed to insert user: {:?}", e);
        if e.to_string().to_lowercase().contains("unique constraint") {
            return AppError::Conflict("A user with this email already exists.".to_string());
        }
        AppError::InternalServerError
    })?;

    debug!(
        "User record created with ID: {}. Inserting Credential record...",
        inserted_user.id
    );

    let provider_id = AuthProvider::find()
        .filter(auth_provider::Column::Name.eq("Password"))
        .one(&txn)
        .await
        .map_err(|e| {
            error!("Database error during auth provider lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("Auth provider 'Password' not found in database");
            AppError::InternalServerError
        })?
        .id;

    let new_credential = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(email.clone()),
        secret: Set(hashed_password),
        provider_id: Set(provider_id),
        user_id: Set(inserted_user.id),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    new_credential.insert(&txn).await.map_err(|e| {
        error!("Failed to insert credential: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Credential record created. Committing transaction.");

    txn.commit().await.map_err(|e| {
        error!("Failed to commit txn: {:?}", e);
        AppError::InternalServerError
    })?;

    info!("Successfully registered user ID: {}", inserted_user.id);

    // ==========================================
    // Generate Verification Token & Send Email
    // ==========================================

    // 1. Create a 24-hour expiration token
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = EmailVerifyClaims {
        sub: inserted_user.id,
        exp: expiration,
        purpose: String::from("email_verification"),
    };

    let verify_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(deps.jwt().secret.as_bytes()),
    )
    .map_err(|e| {
        error!("Failed to sign verification token: {:?}", e);
        AppError::InternalServerError
    })?;

    // 2. Build your deep link
    let deep_link = format!(
        "{}/auth/verify-email?token={}",
        deps.server_url(),
        verify_token
    );

    // 3. Fire the email using the email service
    let email_result = deps
        .email_service()
        .send_verification_email(&email, &deep_link)
        .await;

    // 4. Handle email delivery failures gracefully
    if let Err(e) = email_result {
        error!(
            "User {} registered, but Resend failed to send email: {:?}",
            inserted_user.id, e
        );
        // We still return Ok() because the user IS in the database.
        // The frontend can prompt them to "Resend Verification Email" later.
        return Ok(RegisterResponse {
            user_id: inserted_user.id,
            message: String::from(
                "User registered, but we had trouble sending the verification email. Please try requesting a new one later.",
            ),
        });
    }

    Ok(RegisterResponse {
        user_id: inserted_user.id,
        message: String::from(
            "User registered successfully! Please check your email to verify your account.",
        ),
    })
}

pub async fn verify_email<D: AuthDeps>(deps: &D, token: &str) -> VerifyEmailOutcome {
    info!("Attempting to verify email with provided token");

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60;

    let token_data = match decode::<EmailVerifyClaims>(
        token,
        &DecodingKey::from_secret(deps.jwt().secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("Invalid or expired email verification token: {:?}", e);
            return VerifyEmailOutcome::InvalidOrExpiredToken;
        }
    };

    if token_data.claims.purpose != "email_verification" {
        error!("Attempted to use invalid token purpose for email verification");
        return VerifyEmailOutcome::InvalidTokenPurpose;
    }

    let user_id = token_data.claims.sub;

    let user_record = match user::Entity::find_by_id(user_id).one(deps.db()).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            error!("User {} not found during verification", user_id);
            return VerifyEmailOutcome::UserNotFound;
        }
        Err(e) => {
            error!("Database error finding user during verification: {:?}", e);
            return VerifyEmailOutcome::DatabaseError;
        }
    };

    if user_record.verified_at.is_some() {
        info!("User {} is already verified", user_id);
        return VerifyEmailOutcome::AlreadyVerified;
    }

    let mut active_user: user::ActiveModel = user_record.into();
    active_user.verification_status = Set(String::from("verified"));
    active_user.verified_at = Set(Some(Utc::now()));
    active_user.updated_at = Set(Utc::now());

    if let Err(e) = active_user.update(deps.db()).await {
        error!("Failed to update user verification status: {:?}", e);
        return VerifyEmailOutcome::DatabaseError;
    }

    info!("Successfully verified email for user {}", user_id);
    VerifyEmailOutcome::Success
}
