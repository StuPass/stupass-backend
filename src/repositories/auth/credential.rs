use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr, Set};
use uuid::Uuid;
use chrono::Utc;

use crate::entities::credential;

pub struct CredentialRepository;

impl CredentialRepository {
    pub async fn insert(
        db: &impl ConnectionTrait,
        user_id: Uuid,
        identifier: String,
        hashed_password: String,
    ) -> Result<credential::Model, DbErr> {
        let now = Utc::now();

        let new_credential = credential::ActiveModel {
            id: Set(Uuid::new_v4()),
            identifier: Set(identifier), 
            secret: Set(hashed_password),
            provider_id: Set(1), 
            user_id: Set(user_id),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        new_credential.insert(db).await
    }
}