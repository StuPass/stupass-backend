use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        
        // ==========================================
        // 1. Administrative Location Tables
        // ==========================================
        manager
            .create_table(
                Table::create()
                    .table(City::Table)
                    .if_not_exists()
                    .col(uuid(City::Id).primary_key())
                    .col(string(City::Name).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        // ==========================================
        // 2. Lookup Tables (Category & Condition)
        // ==========================================
        manager
            .create_table(
                Table::create()
                    .table(Category::Table)
                    .if_not_exists()
                    .col(uuid(Category::Id).primary_key())
                    .col(string(Category::Name).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Condition::Table)
                    .if_not_exists()
                    .col(uuid(Condition::Id).primary_key())
                    .col(string(Condition::Name).not_null().unique_key())
                    .col(string_null(Condition::Description))
                    .to_owned(),
            )
            .await?;

        // ==========================================
        // 3. The Unified "Listing" Table 
        // ==========================================
        manager
            .create_table(
                Table::create()
                    .table(Listing::Table)
                    .if_not_exists()
                    .col(uuid(Listing::Id).primary_key())
                    .col(string(Listing::Title).not_null())
                    .col(string(Listing::Description).not_null())
                    .col(string_null(Listing::PictureUrl))
                    .col(string_null(Listing::VideoUrl))
                    .col(integer(Listing::Price).not_null().default(0))
                    .col(integer_null(Listing::OriginalPrice))
                    .col(uuid(Listing::CategoryId).not_null())
                    .col(uuid(Listing::ConditionId).not_null())
                    .col(uuid(Listing::CityId).not_null())
                    .col(string_null(Listing::StreetAddress))
                    .col(string(Listing::Status).not_null().default("available"))
                    .col(uuid(Listing::SellerId).not_null())
                    .col(timestamp(CreatedAt).not_null().default(Expr::current_timestamp()))
                    .col(timestamp(UpdatedAt).not_null().default(Expr::current_timestamp()))
                    .col(timestamp_null(DeletedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-listing-category")
                            .from(Listing::Table, Listing::CategoryId)
                            .to(Category::Table, Category::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-listing-condition")
                            .from(Listing::Table, Listing::ConditionId)
                            .to(Condition::Table, Condition::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-listing-city")
                            .from(Listing::Table, Listing::CityId)
                            .to(City::Table, City::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-listing-seller")
                            .from(Listing::Table, Listing::SellerId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ==========================================
        // 4. Report Table
        // ==========================================
        manager
            .create_table(
                Table::create()
                    .table(Report::Table)
                    .if_not_exists()
                    .col(uuid(Report::Id).primary_key())
                    .col(string(Report::Reason).not_null())
                    .col(string(Report::Status).not_null().default("pending"))
                    .col(string_null(Report::AdminNote))
                    .col(integer(Report::ScoreSubtracted).not_null().default(0))
                    .col(uuid_null(Report::ListingId))
                    .col(uuid(Report::ReporterId).not_null())
                    .col(uuid(Report::ReportedUserId).not_null())
                    .col(timestamp(CreatedAt).not_null().default(Expr::current_timestamp()))
                    .col(timestamp(UpdatedAt).not_null().default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-report-listing")
                            .from(Report::Table, Report::ListingId)
                            .to(Listing::Table, Listing::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-report-reporter")
                            .from(Report::Table, Report::ReporterId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-report-reported-user")
                            .from(Report::Table, Report::ReportedUserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ==========================================
        // 5. Review Table
        // ==========================================
        manager
            .create_table(
                Table::create()
                    .table(Review::Table)
                    .if_not_exists()
                    .col(uuid(Review::Id).primary_key())
                    .col(integer(Review::AttitudeRating).not_null())
                    .col(string(Review::Comment).not_null())
                    .col(string_null(Review::PictureUrl))
                    .col(string_null(Review::VideoUrl))
                    .col(integer(Review::ScoreAdded).not_null().default(0))
                    .col(uuid(Review::WriterId).not_null())
                    .col(uuid(Review::ReceiverId).not_null())
                    .col(timestamp(CreatedAt).not_null().default(Expr::current_timestamp()))
                    .col(timestamp(UpdatedAt).not_null().default(Expr::current_timestamp()))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-review-writer")
                            .from(Review::Table, Review::WriterId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-review-receiver")
                            .from(Review::Table, Review::ReceiverId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ==========================================
        // 6. Add Cometchat Auth token for User.
        // ==========================================
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(string_null(User::CometchatAuthToken))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::CometchatAuthToken)
                    .to_owned(),
            )
            .await?;
        manager.drop_table(Table::drop().table(Review::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Report::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Listing::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Condition::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Category::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(City::Table).to_owned()).await?;
        Ok(())
    }
}

// ==========================================
// IDEN Definitions (Identifiers)
// ==========================================

#[derive(DeriveIden)]
struct CreatedAt;

#[derive(DeriveIden)]
struct UpdatedAt;

#[derive(DeriveIden)]
struct DeletedAt;

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    CometchatAuthToken,
}

#[derive(DeriveIden)]
enum City {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum Category {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum Condition {
    Table,
    Id,
    Name,
    Description,
}

#[derive(DeriveIden)]
enum Listing {
    Table,
    Id,
    Title,
    Description,
    PictureUrl,
    VideoUrl,
    Price,
    OriginalPrice,
    CategoryId,
    ConditionId,
    CityId,
    StreetAddress,
    Status,
    SellerId,
}

#[derive(DeriveIden)]
enum Report {
    Table,
    Id,
    Reason,
    Status,
    AdminNote,
    ScoreSubtracted,
    ListingId,
    ReporterId,
    ReportedUserId,
}

#[derive(DeriveIden)]
enum Review {
    Table,
    Id,
    AttitudeRating,
    Comment,
    PictureUrl,
    VideoUrl,
    ScoreAdded,
    WriterId,
    ReceiverId,
}