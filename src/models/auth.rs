use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

// AuthProvider

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthProvider {
    pub id: i32,
    pub name: String,
}

impl From<crate::entities::auth_provider::Model> for AuthProvider {
    fn from(m: crate::entities::auth_provider::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
        }
    }
}

impl TryFrom<AuthProvider> for crate::entities::auth_provider::ActiveModel {
    type Error = sea_orm::DbErr;

    fn try_from(m: AuthProvider) -> Result<Self, Self::Error> {
        use sea_orm::ActiveValue::Set;
        Ok(Self {
            id: Set(m.id),
            name: Set(m.name),
        })
    }
}

// Credential

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub identifier: String,
    pub secret: String,
    pub provider_id: i32,
    pub user_id: Uuid,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

impl From<crate::entities::credential::Model> for Credential {
    fn from(m: crate::entities::credential::Model) -> Self {
        Self {
            id: m.id,
            identifier: m.identifier,
            secret: m.secret,
            provider_id: m.provider_id,
            user_id: m.user_id,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

impl TryFrom<Credential> for crate::entities::credential::ActiveModel {
    type Error = sea_orm::DbErr;

    fn try_from(m: Credential) -> Result<Self, Self::Error> {
        use sea_orm::ActiveValue::Set;
        Ok(Self {
            id: Set(m.id),
            identifier: Set(m.identifier),
            secret: Set(m.secret),
            provider_id: Set(m.provider_id),
            user_id: Set(m.user_id),
            created_at: Set(m.created_at),
            updated_at: Set(m.updated_at),
        })
    }
}

// Session

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub id: i32,
    pub session_token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub valid_from: DateTimeUtc,
    pub expires_at: DateTimeUtc,
    pub last_refresh: DateTimeUtc,
    pub user_id: Uuid,
}

impl From<crate::entities::session::Model> for Session {
    fn from(m: crate::entities::session::Model) -> Self {
        Self {
            id: m.id,
            session_token_hash: m.session_token_hash,
            ip_address: m.ip_address,
            user_agent: m.user_agent,
            valid_from: m.valid_from,
            expires_at: m.expires_at,
            last_refresh: m.last_refresh,
            user_id: m.user_id,
        }
    }
}

impl TryFrom<Session> for crate::entities::session::ActiveModel {
    type Error = sea_orm::DbErr;

    fn try_from(m: Session) -> Result<Self, Self::Error> {
        use sea_orm::ActiveValue::Set;
        Ok(Self {
            id: Set(m.id),
            session_token_hash: Set(m.session_token_hash),
            ip_address: Set(m.ip_address),
            user_agent: Set(m.user_agent),
            valid_from: Set(m.valid_from),
            expires_at: Set(m.expires_at),
            last_refresh: Set(m.last_refresh),
            user_id: Set(m.user_id),
        })
    }
}

// --- PasswordResetToken ---

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub id: i32,
    pub reset_token_hash: String,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
    pub used_at: Option<DateTimeUtc>,
    pub user_id: Uuid,
}

impl From<crate::entities::password_reset_token::Model> for PasswordResetToken {
    fn from(m: crate::entities::password_reset_token::Model) -> Self {
        Self {
            id: m.id,
            reset_token_hash: m.reset_token_hash,
            created_at: m.created_at,
            expires_at: m.expires_at,
            used_at: m.used_at,
            user_id: m.user_id,
        }
    }
}

impl TryFrom<PasswordResetToken> for crate::entities::password_reset_token::ActiveModel {
    type Error = sea_orm::DbErr;

    fn try_from(m: PasswordResetToken) -> Result<Self, Self::Error> {
        use sea_orm::ActiveValue::Set;
        Ok(Self {
            id: Set(m.id),
            reset_token_hash: Set(m.reset_token_hash),
            created_at: Set(m.created_at),
            expires_at: Set(m.expires_at),
            used_at: Set(m.used_at),
            user_id: Set(m.user_id),
        })
    }
}
