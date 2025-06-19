use sea_orm_migration::{prelude::*, schema::*};

use crate::def::MetaBlob;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MetaBlob::Table)
                    .if_not_exists()
                    .col(string(MetaBlob::Name).primary_key())
                    .col(binary(MetaBlob::Value))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(MetaBlob::Table).to_owned())
            .await
    }
}
