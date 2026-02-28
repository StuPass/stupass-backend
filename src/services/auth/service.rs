use async_trait::async_trait;

use crate::errors::AppError;
use crate::models::auth::*;
use crate::services::auth::{login, password, register, session};
use crate::state::AppState;

use super::register::VerifyEmailOutcome;

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn register(
        &self,
        state: &AppState,
        payload: RegisterRequest,
    ) -> Result<RegisterResponse, AppError>;

    async fn login(
        &self,
        state: &AppState,
        payload: LoginRequest,
    ) -> Result<LoginResponse, AppError>;

    async fn logout(
        &self,
        state: &AppState,
        payload: LogoutRequest,
    ) -> Result<LogoutResponse, AppError>;

    async fn refresh(
        &self,
        state: &AppState,
        payload: RefreshRequest,
    ) -> Result<RefreshResponse, AppError>;

    async fn forgot_password(
        &self,
        state: &AppState,
        payload: ForgotPasswordRequest,
    ) -> Result<ForgotPasswordResponse, AppError>;

    async fn reset_password(
        &self,
        state: &AppState,
        payload: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, AppError>;

    async fn verify_email(&self, state: &AppState, token: &str) -> VerifyEmailOutcome;
}

pub struct AuthServiceImpl;

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn register(
        &self,
        state: &AppState,
        payload: RegisterRequest,
    ) -> Result<RegisterResponse, AppError> {
        register::register_user(state, payload).await
    }

    async fn login(
        &self,
        state: &AppState,
        payload: LoginRequest,
    ) -> Result<LoginResponse, AppError> {
        login::authenticate_user(state, payload).await
    }

    async fn logout(
        &self,
        state: &AppState,
        payload: LogoutRequest,
    ) -> Result<LogoutResponse, AppError> {
        session::invalidate_session(state, payload).await
    }

    async fn refresh(
        &self,
        state: &AppState,
        payload: RefreshRequest,
    ) -> Result<RefreshResponse, AppError> {
        session::refresh_session(state, payload).await
    }

    async fn forgot_password(
        &self,
        state: &AppState,
        payload: ForgotPasswordRequest,
    ) -> Result<ForgotPasswordResponse, AppError> {
        password::send_forgot_password_email(state, payload).await
    }

    async fn reset_password(
        &self,
        state: &AppState,
        payload: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, AppError> {
        password::reset_password(state, payload).await
    }

    async fn verify_email(&self, state: &AppState, token: &str) -> VerifyEmailOutcome {
        register::verify_email(state, token).await
    }
}
