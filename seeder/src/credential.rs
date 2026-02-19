use anyhow::Result;
use bcrypt::{DEFAULT_COST, hash};
use chrono::Utc;
use fake::{Fake, faker::internet::en::Password, rand::SeedableRng, rand::rngs::StdRng};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect,
    QueryTrait, Set,
};
use serde::Serialize;
use stupass_backend::entities::{credential, user};
use uuid::Uuid;

/// Plaintext credential info for export
#[derive(Debug, Clone, Serialize)]
pub struct CredentialRecord {
    pub provider_id: i32,
    pub user_id: Uuid,
    pub identifier: String,
    pub password: String,
}

/// Configuration for credential seeding
pub struct CredentialSeedConfig {
    pub provider_id: i32,
    pub rng_seed: u64,
}

/// Seed credentials for all users. Returns plaintext records of inserted credentials.
pub async fn seed_credentials(
    db: &DatabaseConnection,
    config: CredentialSeedConfig,
) -> Result<Vec<CredentialRecord>> {
    let mut rng = StdRng::seed_from_u64(config.rng_seed);
    let mut records = Vec::new();

    // fetch users without existing credentials for this provider
    let users = user::Entity::find()
        .filter(
            Expr::col(user::Column::Id).not_in_subquery(
                credential::Entity::find()
                    .select_only()
                    .column(credential::Column::UserId)
                    .filter(credential::Column::ProviderId.eq(config.provider_id))
                    .into_query(),
            ),
        )
        .all(db)
        .await?;

    if users.is_empty() {
        return Ok(records);
    }

    let mut models_to_insert: Vec<credential::ActiveModel> = Vec::with_capacity(users.len());
    for u in users {
        let password: String = Password(12..16).fake_with_rng(&mut rng);

        let hashed = hash(&password, DEFAULT_COST)?;
        let now = Utc::now();

        models_to_insert.push(credential::ActiveModel {
            id: Set(Uuid::new_v4()),
            identifier: Set(u.username.clone()),
            secret: Set(hashed),
            provider_id: Set(config.provider_id),
            user_id: Set(u.id),
            created_at: Set(now),
            updated_at: Set(now),
        });

        records.push(CredentialRecord {
            provider_id: config.provider_id,
            user_id: u.id,
            identifier: u.username,
            password,
        });
    }

    if !models_to_insert.is_empty() {
        credential::Entity::insert_many(models_to_insert)
            .exec(db)
            .await?;
    }

    Ok(records)
}
