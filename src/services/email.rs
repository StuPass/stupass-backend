use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use tracing::{error, info};

use crate::errors::AppError;

/// Email service trait for sending various email types
#[async_trait]
pub trait EmailService: Send + Sync {
    /// Send a verification email with the provided deep link
    async fn send_verification_email(
        &self,
        to: &str,
        verification_link: &str,
    ) -> Result<(), AppError>;

    /// Send a password reset email with the provided reset link
    async fn send_password_reset_email(&self, to: &str, reset_link: &str) -> Result<(), AppError>;
}

/// Production email service using Resend API
pub struct ResendEmailService {
    client: Client,
    api_key: String,
    from_email: String,
}

impl ResendEmailService {
    pub fn new(client: Client, api_key: String) -> Self {
        Self {
            client,
            api_key,
            from_email: String::from("noreply@stupass.anhtuanlh.foo"),
        }
    }

    /// Create with custom from email (useful for testing)
    pub fn with_from_email(mut self, from_email: String) -> Self {
        self.from_email = from_email;
        self
    }
}

#[async_trait]
impl EmailService for ResendEmailService {
    async fn send_verification_email(
        &self,
        to: &str,
        verification_link: &str,
    ) -> Result<(), AppError> {
        let resend_url = "https://api.resend.com/emails";

        let html_content = format!(
            r#"
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Welcome to StuPass! 🎓</h2>
            <p style="color: #555; font-size: 16px;">Thanks for signing up. Please verify your email address to activate your account.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{}" style="background-color: #4CAF50; color: white; padding: 14px 25px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    Verify My Email
                </a>
            </div>
            <p style="color: #777; font-size: 14px;">If the button above doesn't work, copy and paste this link into your browser (or tap it on your phone):<br><br>
            <a href="{}" style="color: #4CAF50; word-break: break-all;">{}</a></p>
            <p style="color: #aaa; font-size: 12px; margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px;">If you didn't request this email, you can safely ignore it.</p>
        </div>
        "#,
            verification_link, verification_link, verification_link
        );

        let payload = json!({
            "from": self.from_email,
            "to": [to],
            "subject": "Verify your StuPass Account",
            "html": html_content
        });

        let response = self
            .client
            .post(resend_url)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to reach Resend API: {:?}", e);
                AppError::InternalServerError
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            error!("Resend API rejected the email request: {}", error_text);
            return Err(AppError::InternalServerError);
        }

        info!("Successfully sent verification email via Resend to {}", to);
        Ok(())
    }

    async fn send_password_reset_email(&self, to: &str, reset_link: &str) -> Result<(), AppError> {
        let resend_url = "https://api.resend.com/emails";

        let html_content = format!(
            r#"
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Reset Your StuPass Password</h2>
            <p style="color: #555; font-size: 16px;">We received a request to reset your password. Click the button below to create a new one.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{}" style="background-color: #2196F3; color: white; padding: 14px 25px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    Reset Password
                </a>
            </div>
            <p style="color: #777; font-size: 14px;">If the button above doesn't work, copy and paste this link into your browser:<br><br>
            <a href="{}" style="color: #2196F3; word-break: break-all;">{}</a></p>
            <p style="color: #aaa; font-size: 12px; margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px;">
                This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
            </p>
        </div>
        "#,
            reset_link, reset_link, reset_link
        );

        let payload = json!({
            "from": self.from_email,
            "to": [to],
            "subject": "Reset Your StuPass Password",
            "html": html_content
        });

        let response = self
            .client
            .post(resend_url)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to reach Resend API: {:?}", e);
                AppError::InternalServerError
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Resend API rejected the password reset email request: {}",
                error_text
            );
            return Err(AppError::InternalServerError);
        }

        info!(
            "Successfully sent password reset email via Resend to {}",
            to
        );
        Ok(())
    }
}
