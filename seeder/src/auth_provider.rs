use anyhow::Result;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use stupass_backend::entities::auth_provider;

/// Ensure "Password" auth provider exists. Returns its ID.
pub async fn seed_auth_provider(db: &DatabaseConnection) -> Result<i32> {
    if let Some(p) = auth_provider::Entity::find()
        .filter(auth_provider::Column::Name.eq("Password"))
        .one(db)
        .await?
    {
        return Ok(p.id);
    }

    let p = auth_provider::ActiveModel {
        name: Set("Password".into()),
        ..Default::default()
    }
    .insert(db)
    .await?;

    Ok(p.id)
}
