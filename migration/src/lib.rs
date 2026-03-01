pub use sea_orm_migration::prelude::*;

mod m20260215_000001_init_auth_schema;
mod m20260224_000002_init_stupass_schema;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260215_000001_init_auth_schema::Migration),
            Box::new(m20260224_000002_init_stupass_schema::Migration),
        ]
    }
}
