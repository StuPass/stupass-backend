use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use chrono::Utc;
use fake::{Fake, faker::internet::en::Password, rand::SeedableRng, rand::rngs::StdRng};
use rayon::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, QueryTrait, Set,
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

/// Internal struct for pre-hashing data
struct UserCredentialInput {
    user_id: Uuid,
    identifier: String,
    password: String,
}

/// Internal struct for post-hashing data
struct HashedCredential {
    user_id: Uuid,
    identifier: String,
    password: String,
    hashed: String,
}

/// Seed credentials for all users. Returns plaintext records of inserted credentials.
pub async fn seed_credentials(
    db: &DatabaseConnection,
    config: CredentialSeedConfig,
) -> Result<Vec<CredentialRecord>> {
    let mut rng = StdRng::seed_from_u64(config.rng_seed);

    // Fetch users without existing credentials for this provider
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
        return Ok(Vec::new());
    }

    // Phase 1: Generate plaintext passwords (fast, deterministic)
    let inputs: Vec<UserCredentialInput> = users
        .into_iter()
        .map(|u| {
            let password: String = Password(12..16).fake_with_rng(&mut rng);
            UserCredentialInput {
                user_id: u.id,
                identifier: u.username,
                password,
            }
        })
        .collect();

    // Phase 2: Parallel hashing with argon2 (CPU-bound)
    let hashed: Vec<HashedCredential> = inputs
        .into_par_iter()
        .map(|input| {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let hashed = argon2
                .hash_password(input.password.as_bytes(), &salt)
                .expect("Failed to hash password")
                .to_string();

            HashedCredential {
                user_id: input.user_id,
                identifier: input.identifier,
                password: input.password,
                hashed,
            }
        })
        .collect();

    // Phase 3: Build models and records
    let now = Utc::now();
    let (models_to_insert, records): (Vec<_>, Vec<_>) = hashed
        .into_iter()
        .map(|h| {
            let model = credential::ActiveModel {
                id: Set(Uuid::new_v4()),
                identifier: Set(h.identifier.clone()),
                secret: Set(h.hashed),
                provider_id: Set(config.provider_id),
                user_id: Set(h.user_id),
                created_at: Set(now),
                updated_at: Set(now),
            };

            let record = CredentialRecord {
                provider_id: config.provider_id,
                user_id: h.user_id,
                identifier: h.identifier,
                password: h.password,
            };

            (model, record)
        })
        .unzip();

    // Phase 4: Bulk insert
    if !models_to_insert.is_empty() {
        credential::Entity::insert_many(models_to_insert)
            .exec(db)
            .await?;
    }

    Ok(records)
}
