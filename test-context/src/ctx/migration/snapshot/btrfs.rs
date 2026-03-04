use crate::resource::TestResource;
use anyhow::{Context, anyhow, bail};
use futures::future::BoxFuture;
use postgresql_embedded::{PostgreSQL, Settings};
use std::{
    ffi::OsStr,
    fmt::Debug,
    io,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tokio::fs;
use trustify_common::{config, db::Database};
use trustify_module_storage::service::fs::FileSystemBackend;

#[derive(Clone, Debug)]
struct Command {
    pub btrfs: PathBuf,
    pub store: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl Command {
    pub fn new() -> anyhow::Result<Self> {
        bail!("btrfs is only supported on Linux");
    }
}

#[cfg(target_os = "linux")]
impl Command {
    pub fn is_btrfs(path: impl AsRef<Path>) -> io::Result<bool> {
        const BTRFS_SUPER_MAGIC: nix::libc::c_long = 0x9123683E;

        let stat = nix::sys::statfs::statfs(path.as_ref()).map_err(io::Error::from)?;

        Ok(stat.filesystem_type().0 == BTRFS_SUPER_MAGIC)
    }

    pub fn new() -> anyhow::Result<Self> {
        let btrfs = which::which("btrfs").context(
            r#"unable to locate btrfs:

You can install `btrfs`:
  * On Fedora using: sudo dnf install btrfs-progs

"#,
        )?;

        let store = match std::env::var_os("TRUST_TEST_BTRFS_STORE") {
            Some(store) => Some(PathBuf::from(store)),
            None => std::env::current_dir().ok(),
        }
        .ok_or_else(|| anyhow!("unable to locate btrfs store"))?;

        if !Self::is_btrfs(store.as_path())? {
            bail!(
                r#"btrfs store ({}) is not on a btrfs volume.

You can set `TRUST_TEST_BTRFS_STORE` to a directory on a BTRFS volume mounted with: defaults,user,exec,user_subvol_rm_allowed
"#,
                store.display()
            );
        }

        Ok(Self { btrfs, store })
    }

    async fn execute(
        &self,
        args: impl IntoIterator<Item = impl AsRef<OsStr> + Debug>,
    ) -> anyhow::Result<()> {
        let args = args.into_iter().collect::<Vec<_>>();
        log::info!("{} {args:?}", self.btrfs.display());

        let mut command = tokio::process::Command::new(&self.btrfs);

        command.args(args);

        let status = command.status().await?;

        if !status.success() {
            bail!("btrfs exited with status {}", status);
        }

        Ok(())
    }
}

/// A running content instance
#[derive(Debug)]
pub enum Running {
    /// Plain simple temp dir
    Temporary(TempDir),
    /// Using an existing, ready to use, snapshot
    Existing(BtrfsSnapshot),
    /// A preparation step to create a snapshot
    Collecting(Collect),
}

impl Running {
    pub async fn new(id: impl Into<String>) -> anyhow::Result<Self> {
        let btrfs = match Command::new() {
            Ok(btrfs) => btrfs,
            Err(err) => {
                log::warn!("failed to detect btrfs support: {}", err);
                return Ok(Running::Temporary(TempDir::new()?));
            }
        };

        let id = id.into();

        // detect existing

        let template = btrfs.store.join("templates").join(&id);
        if template.is_dir() {
            return Ok(Running::Existing(BtrfsSnapshot { btrfs, id }));
        }

        // return new collecting

        Ok(Running::Collecting(Collect::new(btrfs, id).await?))
    }
}

/// A mounted snapshot, ready to use
#[derive(Debug)]
pub struct BtrfsSnapshot {
    btrfs: Command,
    id: String,
}

impl BtrfsSnapshot {
    pub async fn start(&self) -> anyhow::Result<BtrfsStarted> {
        // mount

        let snapshot = self.btrfs.store.join("templates").join(&self.id);

        let running = self.btrfs.store.join("running");
        fs::create_dir_all(&running).await?;
        let running = running.join(uuid::Uuid::new_v4().to_string());

        // create volume (running) from snapshot

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                snapshot.as_os_str(),
                running.as_os_str(),
            ])
            .await?;

        // create instances

        let storage = FileSystemBackend::for_test_in(running.join("storage")).await?;

        let db_base = running.join("db");
        let settings = Settings {
            data_dir: db_base.join("data"),
            temporary: false,
            ..Default::default()
        };
        let mut psql = PostgreSQL::new(settings);
        psql.setup().await?;
        psql.start().await?;

        let db = config::Database::from_port(psql.settings().port)?;

        // done

        Ok(BtrfsStarted {
            btrfs: self.btrfs.clone(),
            storage,
            db: Database::new(&db).await?,
            psql,
            path: running,
        })
    }
}

pub struct BtrfsStarted {
    storage: FileSystemBackend,
    psql: PostgreSQL,
    db: Database,
    path: PathBuf,
    btrfs: Command,
}

impl BtrfsStarted {
    pub fn storage(&self) -> &FileSystemBackend {
        &self.storage
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn settings(&self) -> &Settings {
        self.psql.settings()
    }

    pub async fn stop(self) -> anyhow::Result<()> {
        // stop the database

        let _ = self.psql.stop().await;

        // delete the subvolume

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("delete"),
                self.path.as_os_str(),
            ])
            .await?;

        // done

        Ok(())
    }
}

impl TestResource for BtrfsStarted {
    fn drop(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let _ = self.stop().await;
        })
    }
}

#[derive(Debug)]
pub struct Collect {
    // directory to prepare in
    path: PathBuf,
    btrfs: Command,
    id: String,
}

impl Collect {
    async fn new(btrfs: Command, id: String) -> anyhow::Result<Self> {
        let path = btrfs.store.join("prepare").join(&id);

        if path.exists() {
            log::info!(
                "Deleting existing preparation directory: {}",
                path.display()
            );

            btrfs
                .execute([
                    OsStr::new("subvolume"),
                    OsStr::new("delete"),
                    path.as_os_str(),
                ])
                .await?;
        }

        btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("create"),
                path.as_os_str(),
            ])
            .await?;

        Ok(Self { path, btrfs, id })
    }

    pub async fn create(self, psql: PostgreSQL) -> anyhow::Result<BtrfsSnapshot> {
        log::info!("Collecting snapshot");

        // stop the instance to allow creating a consistent snapshot

        psql.stop().await?;

        // take the snapshot

        let target = self.btrfs.store.join("templates");
        fs::create_dir_all(&target).await?;
        let target = target.join(&self.id);

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("snapshot"),
                self.path.as_os_str(),
                target.as_os_str(),
            ])
            .await?;

        // now delete the prepared volume

        self.btrfs
            .execute([
                OsStr::new("subvolume"),
                OsStr::new("delete"),
                self.path.as_os_str(),
            ])
            .await?;

        // return the result

        Ok(BtrfsSnapshot {
            btrfs: self.btrfs,
            id: self.id,
        })
    }
}

impl AsRef<Path> for Collect {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
