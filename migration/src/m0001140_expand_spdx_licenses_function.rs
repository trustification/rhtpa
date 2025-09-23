use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Indexes supporting the query on licensing_infos table added with the SQL script below
        manager
            .create_index(
                Index::create()
                    .table(LicensingInfos::Table)
                    .name(Indexes::SbomIdIdx.to_string())
                    .col(LicensingInfos::SbomId)
                    .to_owned(),
            )
            .await?;
        // Indexes supporting the sorting on licensing_infos table added with the SQL script below
        manager
            .create_index(
                Index::create()
                    .table(LicensingInfos::Table)
                    .name(Indexes::LicenseIdIdx.to_string())
                    .col(LicensingInfos::LicenseId)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0001140_expand_spdx_licenses_function/expand_up.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS expand_license_expression(TEXT, UUID);")
            .await
            .map(|_| ())?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(LicensingInfos::Table)
                    .name(Indexes::LicenseIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(LicensingInfos::Table)
                    .name(Indexes::SbomIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    LicenseIdIdx,
    SbomIdIdx,
}

#[derive(DeriveIden)]
pub enum LicensingInfos {
    Table,
    LicenseId,
    SbomId,
}
