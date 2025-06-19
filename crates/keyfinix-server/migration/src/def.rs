use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum MetaBlob {
    Table,
    Name,
    Value,
}
