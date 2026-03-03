use crate::MigratorTest;
use migration::{
    Migrator,
    data::{Database, Direction, MigrationWithData, Options, Runner},
};
use sea_orm_migration::MigratorTrait;
use std::num::NonZeroUsize;
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyMigrationContext, commit, dump};

commit!(Commit("6d3ea814b4b44fe16ea8f21724dda5abb0fc7932"));

#[test_context(TrustifyMigrationContext<Commit>)]
#[test(tokio::test)]
async fn examples(
    ctx: &TrustifyMigrationContext<Commit>, /* commit previous to this PR */
) -> Result<(), anyhow::Error> {
    let migrations = vec!["m0002010_add_advisory_scores".into()];

    // first run the data migration
    Runner {
        direction: Direction::Up,
        storage: ctx.storage.clone().into(),
        migrations: migrations.clone(),
        database: Database::Provided(ctx.db.clone().into_connection()),
        options: Default::default(),
    }
    .run::<Migrator>()
    .await?;

    // now run the migrations, but skip the already run migration

    MigrationWithData::run_with_test(
        ctx.storage.clone(),
        Options {
            skip: migrations,
            ..Default::default()
        },
        async { MigratorTest::up(&ctx.db, None).await },
    )
    .await?;

    // done

    Ok(())
}

// A dump created before merging the SBOM CVSS enhancements
dump!(
    Ds4("https://trustify-dumps-ds4.s3.eu-west-1.amazonaws.com/20251104T095645Z")
        .storage_file("dump.tar.gz")
        .no_digests()
        .strip(5)
        .fix_zstd()
);

/// Test the performance of applying the data migration of `m0002010`.
///
/// **NOTE:** If this test runs out of disk space, you can set `TMPDIR` to a directory with more
/// space.
#[test_context(TrustifyMigrationContext<Ds4>)]
#[test(tokio::test)]
#[cfg_attr(
    not(feature = "long_running"),
    ignore = "enable with: cargo test --features long_running"
)]
async fn performance(ctx: &TrustifyMigrationContext<Ds4>) -> Result<(), anyhow::Error> {
    MigrationWithData::run_with_test(
        ctx.storage.clone(),
        Options {
            concurrent: NonZeroUsize::new(32).unwrap(),
            ..Options::default()
        },
        async { MigratorTest::up(&ctx.db, None).await },
    )
    .await?;

    // done

    Ok(())
}
