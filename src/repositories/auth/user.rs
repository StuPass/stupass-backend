use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr, Set};
use uuid::Uuid;
use chrono::Utc;

use crate::entities::user;

pub struct UserRepository;

impl UserRepository {
    pub async fn insert(
        db: &impl ConnectionTrait, 
        phone: String,
        full_name: String,
        school_id: String,
        student_id: String,
    ) -> Result<user::Model, DbErr> {
        let now = Utc::now();
        
        let new_user = user::ActiveModel {
            id: Set(Uuid::new_v4()),
            phone: Set(phone),
            full_name: Set(full_name),
            school_id: Set(school_id),
            student_id: Set(student_id),
            reputation_score: Set(10),
            verification_status: Set(String::from("pending")),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        new_user.insert(db).await
    }
}