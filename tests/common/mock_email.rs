#![allow(dead_code, unused_imports)]

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use stupass_backend::errors::AppError;
use stupass_backend::services::email::EmailService;

/// Type of email sent
#[derive(Debug, Clone, Default)]
pub enum EmailType {
    #[default]
    Verification,
    PasswordReset,
}

/// Record of an email call
#[derive(Debug, Clone, Default)]
pub struct EmailCall {
    pub to: String,
    pub link: String,
    pub email_type: EmailType,
}

/// Mock email service for testing
pub struct MockEmailService {
    pub calls: Arc<Mutex<Vec<EmailCall>>>,
    pub should_fail: Arc<Mutex<bool>>,
}

impl MockEmailService {
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    /// Configure the mock to return errors
    pub fn set_should_fail(&self, value: bool) {
        *self.should_fail.lock().unwrap() = value;
    }

    /// Get all recorded email calls
    pub fn get_calls(&self) -> Vec<EmailCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Clear all recorded calls
    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }

    /// Check if any verification email was sent
    pub fn has_verification_email(&self) -> bool {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| matches!(c.email_type, EmailType::Verification))
    }

    /// Check if any password reset email was sent
    pub fn has_password_reset_email(&self) -> bool {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| matches!(c.email_type, EmailType::PasswordReset))
    }
}

#[async_trait]
impl EmailService for MockEmailService {
    async fn send_verification_email(
        &self,
        to: &str,
        verification_link: &str,
    ) -> Result<(), AppError> {
        if *self.should_fail.lock().unwrap() {
            return Err(AppError::InternalServerError);
        }

        self.calls.lock().unwrap().push(EmailCall {
            to: to.to_string(),
            link: verification_link.to_string(),
            email_type: EmailType::Verification,
        });
        Ok(())
    }

    async fn send_password_reset_email(&self, to: &str, reset_link: &str) -> Result<(), AppError> {
        if *self.should_fail.lock().unwrap() {
            return Err(AppError::InternalServerError);
        }

        self.calls.lock().unwrap().push(EmailCall {
            to: to.to_string(),
            link: reset_link.to_string(),
            email_type: EmailType::PasswordReset,
        });
        Ok(())
    }
}

impl Default for MockEmailService {
    fn default() -> Self {
        Self::new()
    }
}
