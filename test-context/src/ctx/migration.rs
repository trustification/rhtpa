use crate::{
    TrustifyTestContext,
    migration::Migration,
    migration::{Dump, Dumps},
};
use anyhow::Context;
use std::{borrow::Cow, marker::PhantomData, ops::Deref};
use tar::Archive;
use test_context::AsyncTestContext;
use trustify_common::decompress::decompress_read;
use trustify_db::embedded::{Options, default_settings};
use trustify_module_storage::service::fs::FileSystemBackend;

#[macro_export]
macro_rules! commit {
    ($t:ident($id:literal)) => {
        pub struct $t;

        impl $crate::ctx::DumpId for $t {
            fn dump_id() -> $crate::ctx::MigrationSource {
                $crate::ctx::MigrationSource::Migration(Some($id))
            }
        }
    };
}

#[macro_export]
macro_rules! dump {
    ($t:ident($url:literal $(, $($rest:tt)*)? )) => {
        $crate::dump!(@parse $t, $url, db = "dump.sql.gz", storage = "dump.tar", digests = true, $($($rest)*)?);
    };

    (@parse $t:ident, $url:literal, db = $db:literal, storage = $storage:literal, digests = $digests:expr, db = $new_db:literal, $($rest:tt)*) => {
        $crate::dump!(@parse $t, $url, db = $new_db, storage = $storage, digests = $digests, $($rest)*);
    };
    (@parse $t:ident, $url:literal, db = $db:literal, storage = $storage:literal, digests = $digests:expr, storage = $new_storage:literal, $($rest:tt)*) => {
        $crate::dump!(@parse $t, $url, db = $db, storage = $new_storage, digests = $digests, $($rest)*);
    };
    (@parse $t:ident, $url:literal, db = $db:literal, storage = $storage:literal, digests = $digests:expr, no_digests, $($rest:tt)*) => {
        $crate::dump!(@parse $t, $url, db = $db, storage = $storage, digests = false, $($rest)*);
    };

    (@parse $t:ident, $url:literal, db = $db:literal, storage = $storage:literal, digests = $digests:expr,) => {
        $crate::dump!(@emit $t, $url, $db, $storage, $digests);
    };

    (@emit $t:ident, $url:literal, $db:literal, $storage:literal, $digests:expr) => {
        pub struct $t;

        impl $crate::ctx::DumpId for $t {
            fn dump_id() -> $crate::ctx::Source {
                $crate::ctx::Source::Dump {
                    base_url: $url,
                    db_file: $db,
                    storage_file: $storage,
                    digests: $digests,
                }
            }
        }
    };
}

pub enum Source {
    Migration(Option<&'static str>),
    Dump {
        /// base URL to the dump files
        base_url: &'static str,
        /// DB file name
        db_file: &'static str,
        /// storage archive
        storage_file: &'static str,
        /// if there are digests for the files
        digests: bool,
    },
}

pub trait DumpId {
    fn dump_id() -> Source;
}

impl DumpId for () {
    fn dump_id() -> Source {
        Source::Migration(None)
    }
}

/// Creates a database and imports the previous DB and storage dump.
pub struct TrustifyMigrationContext<ID: DumpId = ()>(
    pub(crate) TrustifyTestContext,
    PhantomData<ID>,
);

impl<ID: DumpId> Deref for TrustifyMigrationContext<ID> {
    type Target = TrustifyTestContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<ID: DumpId> TrustifyMigrationContext<ID> {
    pub async fn new() -> anyhow::Result<Self> {
        let (base, db_file, storage_file) = match ID::dump_id() {
            Source::Migration(migration) => {
                let id: Cow<'static, str> = match migration {
                    Some(id) => format!("commit-{id}").into(),
                    None => "latest".into(),
                };
                let migration = Migration::new().context("failed to create migration manager")?;
                let base = migration.provide(&id).await?;
                (base, "dump.sql.xz", "dump.tar")
            }

            Source::Dump {
                base_url,
                db_file,
                storage_file,
                digests,
            } => {
                let base = Dumps::new()?
                    .provide(Dump {
                        url: base_url,
                        files: &[db_file, storage_file],
                        digests,
                    })
                    .await?;

                (base, db_file, storage_file)
            }
        };

        let storage_file = base.join(storage_file);
        log::info!("Importing dump: {}", storage_file.display());

        // create storage

        let (storage, tmp) = FileSystemBackend::for_test()
            .await
            .expect("Unable to create storage backend");

        let source = decompress_read(storage_file).context("failed to open storage dump")?;

        let mut archive = Archive::new(source);
        archive
            .unpack(tmp.path())
            .context("failed to unpack storage dump")?;

        log::info!("Storage unpacked");

        // create DB

        let settings = default_settings().context("unable to create default settings")?;

        let (db, postgresql) = trustify_db::embedded::create_for(
            settings,
            Options {
                source: trustify_db::embedded::Source::Import(base.join(db_file)),
            },
        )
        .await
        .context("failed to create an embedded database")?;

        log::info!("Database imported");

        Ok(Self(
            TrustifyTestContext::new(db, storage, tmp, postgresql).await,
            Default::default(),
        ))
    }
}

impl<ID: DumpId> AsyncTestContext for TrustifyMigrationContext<ID> {
    async fn setup() -> Self {
        Self::new()
            .await
            .expect("failed to create migration context")
    }
}
