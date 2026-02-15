use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // AuthProvider
        manager
            .create_table(
                Table::create()
                    .table(AuthProvider::Table)
                    .if_not_exists()
                    .col(pk_auto(AuthProvider::Id).primary_key()) // Integer PK
                    .col(string(AuthProvider::Name).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        // User
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(uuid(User::Id).primary_key()) // UUID PK
                    .col(string(User::Username).not_null().unique_key())
                    .col(string(User::Email).not_null().unique_key())
                    .col(string(User::Phone).not_null().unique_key())
                    .col(string(User::FullName).not_null())
                    .col(string_null(User::AvatarUrl))
                    .col(string_null(User::Bio))
                    .col(date_null(User::DateOfBirth))
                    .col(string(User::SchoolId).not_null())
                    .col(string(User::StudentId).not_null())
                    .col(integer(User::ReputationScore).default(0))
                    .col(
                        string(User::VerificationStatus)
                            .not_null()
                            .default("unverified"),
                    )
                    .col(timestamp_null(User::VerifiedAt))
                    .col(timestamp_null(User::StudentStatusExpiresAt))
                    .col(
                        timestamp(CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_null(DeletedAt))
                    .index(
                        Index::create()
                            .name("idx-unique-school-student")
                            .col(User::SchoolId)
                            .col(User::StudentId)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        // Credential (Ref User, AuthProvider)
        manager
            .create_table(
                Table::create()
                    .table(Credential::Table)
                    .if_not_exists()
                    .col(uuid(Credential::Id).primary_key()) // UUID PK
                    .col(string(Credential::Identifier).not_null())
                    .col(string(Credential::Secret).not_null())
                    .col(integer(Credential::ProviderId).not_null()) // Integer FK -> AuthProvider
                    .col(uuid(Credential::UserId).not_null()) // UUID FK -> User
                    .col(
                        timestamp(CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-credential-user")
                            .from(Credential::Table, Credential::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-credential-auth-provider")
                            .from(Credential::Table, Credential::ProviderId)
                            .to(AuthProvider::Table, AuthProvider::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Restrict),
                    )
                    .index(
                        Index::create()
                            .name("idx-unique-provider-identifier")
                            .col(Credential::ProviderId)
                            .col(Credential::Identifier)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        // Session (Ref User)
        manager
            .create_table(
                Table::create()
                    .table(Session::Table)
                    .if_not_exists()
                    .col(pk_auto(Session::Id).primary_key()) // Integer PK (Ephemeral)
                    .col(string(Session::SessionTokenHash).not_null())
                    .col(string_null(Session::IpAddress))
                    .col(string_null(Session::UserAgent))
                    .col(
                        timestamp(Session::ValidFrom)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp(Session::ExpiresAt).not_null())
                    .col(
                        timestamp(Session::LastRefresh)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(uuid(Session::UserId).not_null()) // UUID FK -> User
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-session-user")
                            .from(Session::Table, Session::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .name("idx-session-session-token-hash")
                            .col(Session::SessionTokenHash)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        // PasswordResetToken (Ref User)
        manager
            .create_table(
                Table::create()
                    .table(PasswordResetToken::Table)
                    .if_not_exists()
                    .col(pk_auto(PasswordResetToken::Id).primary_key()) // Integer PK (Ephemeral)
                    .col(string(PasswordResetToken::ResetTokenHash).not_null())
                    .col(
                        timestamp(CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp(PasswordResetToken::ExpiresAt).not_null())
                    .col(timestamp_null(PasswordResetToken::UsedAt))
                    .col(uuid(PasswordResetToken::UserId).not_null()) // UUID FK -> User
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-password-reset-token-user")
                            .from(PasswordResetToken::Table, PasswordResetToken::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .name("idx-password-reset-token-reset-token-hash")
                            .col(PasswordResetToken::ResetTokenHash)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop Dependents
        manager
            .drop_table(Table::drop().table(PasswordResetToken::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Credential::Table).to_owned())
            .await?;

        // Drop Parents
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(AuthProvider::Table).to_owned())
            .await?;

        Ok(())
    }
}

// --- IDEN Definitions ---

#[derive(DeriveIden)]
struct CreatedAt;

#[derive(DeriveIden)]
struct UpdatedAt;

#[derive(DeriveIden)]
struct DeletedAt;

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    Identifier,
    Secret,
    UserId,
    ProviderId,
}

#[derive(DeriveIden)]
enum Session {
    Table,
    Id,
    SessionTokenHash,
    IpAddress,
    UserAgent,
    ValidFrom,
    ExpiresAt,
    LastRefresh,
    UserId,
}

#[derive(DeriveIden)]
enum PasswordResetToken {
    Table,
    Id,
    ResetTokenHash,
    ExpiresAt,
    UsedAt,
    UserId,
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    Username,
    Email,
    Phone,
    FullName,
    AvatarUrl,
    Bio,
    DateOfBirth,
    SchoolId,
    StudentId,
    ReputationScore,
    VerificationStatus,
    VerifiedAt,
    StudentStatusExpiresAt,
}

#[derive(DeriveIden)]
enum AuthProvider {
    Table,
    Id,
    Name,
}
