use reqwest::Client;
use serde_json::json;
use tracing::{error, info};
use crate::errors::AppError;

/// Sends a password reset email using the Resend REST API
pub async fn send_password_reset_email(
    http_client: &Client,
    resend_api_key: &str,
    to_email: &str,
    reset_link: &str,
) -> Result<(), AppError> {

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
        "from": "noreply@stupass.anhtuanlh.foo",
        "to": [to_email],
        "subject": "Reset Your StuPass Password",
        "html": html_content
    });

    let response = http_client
        .post(resend_url)
        .bearer_auth(resend_api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to reach Resend API: {:?}", e);
            AppError::InternalServerError
        })?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("Resend API rejected the password reset email request: {}", error_text);
        return Err(AppError::InternalServerError);
    }

    info!("Successfully sent password reset email via Resend to {}", to_email);
    Ok(())
}
