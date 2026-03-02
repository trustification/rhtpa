use crate::{
    TrustifyTestContext,
    migration::Migration,
    migration::{Dump, Dumps},
};
use anyhow::Context;
use std::{
    borrow::Cow, fs::OpenOptions, io::Write, marker::PhantomData, ops::Deref, path::PathBuf,
};
use tar::Archive;
use test_context::AsyncTestContext;
use trustify_common::decompress::decompress_read;
use trustify_db::embedded::{Options, default_settings};
use trustify_module_storage::service::fs::FileSystemBackend;
use walkdir::WalkDir;

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
    ($t:ident($url:literal) $($chain:tt)*) => {
        pub struct $t;

        impl $crate::ctx::DumpId for $t {
            fn dump_id() -> $crate::ctx::Source {
                $crate::ctx::Source::Dump(
                    $crate::ctx::DumpSource::new($url) $($chain)*
                )
            }
        }
    };
}

pub struct DumpSource {
    pub base_url: &'static str,
    pub db_file: &'static str,
    pub storage_file: &'static str,
    pub digests: bool,
    pub strip: usize,
    pub fix_zstd: bool,
}

impl DumpSource {
    pub fn new(base_url: &'static str) -> Self {
        Self {
            base_url,
            db_file: "dump.sql.gz",
            storage_file: "dump.tar",
            digests: true,
            strip: 0,
            fix_zstd: false,
        }
    }

    pub fn db_file(mut self, v: &'static str) -> Self {
        self.db_file = v;
        self
    }

    pub fn storage_file(mut self, v: &'static str) -> Self {
        self.storage_file = v;
        self
    }

    pub fn digests(mut self, v: bool) -> Self {
        self.digests = v;
        self
    }

    pub fn no_digests(self) -> Self {
        self.digests(false)
    }

    pub fn strip(mut self, v: usize) -> Self {
        self.strip = v;
        self
    }

    /// Appends the zstd EOF marker (`[0x01, 0x00, 0x00]`) to all `.zstd` files in the storage
    /// directory after unpacking. Older dump generation did not properly close the zstd stream,
    /// leaving the EOF marker unwritten.
    pub fn fix_zstd(mut self) -> Self {
        self.fix_zstd = true;
        self
    }
}

pub enum Source {
    Migration(Option<&'static str>),
    Dump(DumpSource),
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
        let (base, db_file, storage_file, strip, fix_zstd) = match ID::dump_id() {
            Source::Migration(migration) => {
                let id: Cow<'static, str> = match migration {
                    Some(id) => format!("commit-{id}").into(),
                    None => "latest".into(),
                };
                let migration = Migration::new().context("failed to create migration manager")?;
                let base = migration.provide(&id).await?;
                (base, "dump.sql.xz", "dump.tar", 0usize, false)
            }

            Source::Dump(DumpSource {
                base_url,
                db_file,
                storage_file,
                digests,
                strip,
                fix_zstd,
            }) => {
                let base = Dumps::new()?
                    .provide(Dump {
                        url: base_url,
                        files: &[db_file, storage_file],
                        digests,
                    })
                    .await?;

                (base, db_file, storage_file, strip, fix_zstd)
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
        if strip == 0 {
            archive
                .unpack(tmp.path())
                .context("failed to unpack storage dump")?;
        } else {
            for entry in archive
                .entries()
                .context("failed to read storage archive entries")?
            {
                let mut entry = entry.context("failed to read storage archive entry")?;
                let path = entry
                    .path()
                    .context("failed to get entry path")?
                    .into_owned();
                let stripped: PathBuf = path.components().skip(strip).collect();
                if stripped.as_os_str().is_empty() {
                    continue;
                }
                // NOTE: `unpack` (vs `unpack_in`) has no path traversal protection, but
                // this is test-only code and the archive content is generated by us and trusted.
                entry
                    .unpack(tmp.path().join(stripped))
                    .context("failed to unpack storage archive entry")?;
            }
        }

        log::info!("Storage unpacked");

        if fix_zstd {
            const ZSTD_EOF_BYTES: [u8; 3] = [0x01, 0x00, 0x00];
            for entry in WalkDir::new(tmp.path()) {
                let entry = entry.context("failed to walk storage directory")?;
                if entry.file_type().is_file()
                    && entry.path().extension().and_then(|e| e.to_str()) == Some("zstd")
                {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(entry.path())
                        .with_context(|| {
                            format!("failed to open zstd file: {}", entry.path().display())
                        })?;
                    file.write_all(&ZSTD_EOF_BYTES).with_context(|| {
                        format!("failed to append EOF bytes to: {}", entry.path().display())
                    })?;
                }
            }
            log::info!("Fixed zstd EOF bytes");
        }

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
