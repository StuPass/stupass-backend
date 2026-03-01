use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::error;
use uuid::Uuid;

use crate::{errors::AppError, models::auth::Claims};

// ============================================================================
// Token Generation Helpers
// ============================================================================

/// Generate a 64-character random session token (base64-encoded)
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 48]; // 48 bytes -> 64 base64 chars
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token using SHA256
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a JWT access token
pub fn generate_access_token(
    user_id: Uuid,
    secret: &str,
    expiry_seconds: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = now + Duration::seconds(expiry_seconds);

    // TODO: Investigate try_into/i64 type for safer exp/iat dtype
    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| {
        error!("Failed to encode JWT: {:?}", e);
        AppError::InternalServerError(e.to_string())
    })
}
