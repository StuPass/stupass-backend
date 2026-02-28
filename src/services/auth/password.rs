use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, EntityTrait, Set, TransactionTrait};
use tokio::task;
use tracing::{error, info};

use crate::{
    entities::prelude::{AuthProvider, Credential, PasswordResetToken, Session, User},
    entities::{auth_provider, credential, password_reset_token, session, user},
    errors::AppError,
    models::auth::{
        ForgotPasswordRequest, ForgotPasswordResponse, MessageResponse, ResetPasswordRequest,
        ResetPasswordResponse,
    },
    state::AppState,
    utils::jwt_token::*,
};

pub async fn reset_password(
    state: &AppState,
    req: ResetPasswordRequest,
) -> Result<ResetPasswordResponse, AppError> {
    let ResetPasswordRequest {
        token,
        new_password,
    } = req;

    info!("Processing password reset request");

    // --- 1. Hash the incoming token ---
    let token_hash = hash_token(&token);

    // --- 2. Begin transaction early for atomic token validation ---
    let txn = state.db.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 3. Find and lock the reset token record within transaction ---
    // Using find() inside transaction; for row-level locking you'd use SELECT FOR UPDATE
    // but SeaORM's SQLite backend has limited support. The transaction itself provides
    // isolation for our check-then-act pattern.
    let reset_record = PasswordResetToken::find()
        .filter(password_reset_token::Column::ResetTokenHash.eq(&token_hash))
        .one(&txn)
        .await
        .map_err(|e| {
            error!("Database error during reset token lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            info!("Invalid password reset token");
            AppError::BadRequest(String::from("Invalid or expired reset token"))
        })?;

    // --- 4. Validate token: check expiry ---
    let now = Utc::now();
    if reset_record.expires_at < now {
        info!("Password reset token has expired");
        return Err(AppError::BadRequest(String::from(
            "Reset token has expired",
        )));
    }

    // --- 5. Validate token: check if already used ---
    // Now safe from race condition since we're in a transaction
    if reset_record.used_at.is_some() {
        info!("Password reset token already used");
        return Err(AppError::BadRequest(String::from(
            "Reset token has already been used",
        )));
    }

    let user_id = reset_record.user_id;

    // --- 6. Hash the new password ---
    let hashed_password = task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password hashing: {:?}", e);
        AppError::InternalServerError
    })?
    .map_err(|e| {
        error!("Failed to hash new password: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 7. Find the "Password" provider ---
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

    // --- 8. Find and update the credential ---
    let credential_record = Credential::find()
        .filter(credential::Column::UserId.eq(user_id))
        .filter(credential::Column::ProviderId.eq(provider_id))
        .one(&txn)
        .await
        .map_err(|e| {
            error!("Database error during credential lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("No password credential found for user {}", user_id);
            AppError::InternalServerError
        })?;

    let mut cred_active: credential::ActiveModel = credential_record.into();
    cred_active.secret = Set(hashed_password);
    cred_active.updated_at = Set(now);

    cred_active.update(&txn).await.map_err(|e| {
        error!("Failed to update credential: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 9. Mark reset token as used ---
    let mut token_active: password_reset_token::ActiveModel = reset_record.into();
    token_active.used_at = Set(Some(now));

    token_active.update(&txn).await.map_err(|e| {
        error!("Failed to mark reset token as used: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 10. Invalidate all sessions for this user (security measure) ---
    let delete_result = Session::delete_many()
        .filter(session::Column::UserId.eq(user_id))
        .exec(&txn)
        .await
        .map_err(|e| {
            error!("Failed to invalidate sessions: {:?}", e);
            AppError::InternalServerError
        })?;

    info!(
        "Invalidated {} sessions for user {}",
        delete_result.rows_affected, user_id
    );

    // --- 11. Commit transaction ---
    txn.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {:?}", e);
        AppError::InternalServerError
    })?;

    info!("Successfully reset password for user {}", user_id);

    Ok(ResetPasswordResponse(MessageResponse {
        message: String::from(
            "Password has been reset successfully. Please log in with your new password.",
        ),
    }))
}

pub async fn send_forgot_password_email(
    state: &AppState,
    req: ForgotPasswordRequest,
) -> Result<ForgotPasswordResponse, AppError> {
    let ForgotPasswordRequest { email } = req;

    info!("Password reset requested for email: {}", email);

    // --- Rate limiting check (3 requests per hour per email) ---
    if let Err(remaining_secs) = state.rate_limiter.check_password_reset(&email) {
        info!(
            "Password reset rate limited for email: {}. Try again in {} seconds",
            email, remaining_secs
        );
        // Still return success to prevent email enumeration
        return Ok(ForgotPasswordResponse(MessageResponse {
            message: format!(
                "If an account with that email exists, we've sent a password reset link.\
                 \n\nNote: Too many requests. Please try again in {} minutes.",
                remaining_secs / 60 + 1
            ),
        }));
    }

    let success_response = || {
        ForgotPasswordResponse(MessageResponse {
            message: String::from(
                "If an account with that email exists, we've sent a password reset link.",
            ),
        })
    };

    // --- 1. Find user by email ---
    let user_record = User::find()
        .filter(user::Column::Email.eq(&email))
        .one(&state.db)
        .await;

    // Handle lookup result - we proceed silently on errors to prevent enumeration
    let user = match user_record {
        Ok(Some(u)) => u,
        Ok(None) => {
            info!(
                "No user found with email: {} - returning success anyway",
                email
            );
            return Ok(success_response());
        }
        Err(e) => {
            error!("Database error during password reset lookup: {:?}", e);
            return Ok(success_response());
        }
    };

    // --- 2. Generate reset token (64-char random string) ---
    let reset_token = generate_session_token();
    let reset_token_hash = hash_token(&reset_token);

    // --- 3. Calculate expiry (1 hour from now) ---
    let now = Utc::now();
    let expires_at = now + Duration::hours(1);

    // --- 4. Store token hash in database ---
    let new_reset_token = password_reset_token::ActiveModel {
        reset_token_hash: Set(reset_token_hash),
        created_at: Set(now),
        expires_at: Set(expires_at),
        used_at: Set(None),
        user_id: Set(user.id),
        ..Default::default()
    };

    if let Err(e) = new_reset_token.insert(&state.db).await {
        error!("Failed to store password reset token: {:?}", e);
        return Ok(success_response());
    }

    // --- 5. Build reset link (frontend URL with token) ---
    let reset_link = format!("{}/reset-password?token={}", state.fe_url, reset_token);

    // --- 6. Send password reset email ---
    let email_result = state
        .email_service
        .send_password_reset_email(&email, &reset_link)
        .await;

    if let Err(e) = email_result {
        error!("Failed to send password reset email to {}: {:?}", email, e);
        // Still return success to prevent enumeration
    }

    Ok(success_response())
}
