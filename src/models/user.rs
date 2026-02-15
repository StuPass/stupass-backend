use serde::{Deserialize, Serialize};
use sea_orm::entity::prelude::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub phone: String,
    pub full_name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub date_of_birth: Option<Date>,
    pub school_id: String,
    pub student_id: String,
    pub reputation_score: i32,
    pub verification_status: String,
    pub verified_at: Option<DateTimeUtc>,
    pub student_status_expires_at: Option<DateTimeUtc>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub deleted_at: Option<DateTimeUtc>,
}

impl From<crate::entities::user::Model> for User {
    fn from(m: crate::entities::user::Model) -> Self {
        Self {
            id: m.id,
            username: m.username,
            email: m.email,
            phone: m.phone,
            full_name: m.full_name,
            avatar_url: m.avatar_url,
            bio: m.bio,
            date_of_birth: m.date_of_birth,
            school_id: m.school_id,
            student_id: m.student_id,
            reputation_score: m.reputation_score,
            verification_status: m.verification_status,
            verified_at: m.verified_at,
            student_status_expires_at: m.student_status_expires_at,
            created_at: m.created_at,
            updated_at: m.updated_at,
            deleted_at: m.deleted_at,
        }
    }
}

impl TryFrom<User> for crate::entities::user::ActiveModel {
    type Error = sea_orm::DbErr;

    fn try_from(m: User) -> Result<Self, Self::Error> {
        use sea_orm::ActiveValue::Set;
        Ok(Self {
            id: Set(m.id),
            username: Set(m.username),
            email: Set(m.email),
            phone: Set(m.phone),
            full_name: Set(m.full_name),
            avatar_url: Set(m.avatar_url),
            bio: Set(m.bio),
            date_of_birth: Set(m.date_of_birth),
            school_id: Set(m.school_id),
            student_id: Set(m.student_id),
            reputation_score: Set(m.reputation_score),
            verification_status: Set(m.verification_status),
            verified_at: Set(m.verified_at),
            student_status_expires_at: Set(m.student_status_expires_at),
            created_at: Set(m.created_at),
            updated_at: Set(m.updated_at),
            deleted_at: Set(m.deleted_at),
        })
    }
}
