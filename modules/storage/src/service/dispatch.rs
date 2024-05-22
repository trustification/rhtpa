use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use sha2::{digest::Output, Sha256};

use trustify_common::hash::HashKey;

use super::*;

/// A common backend, dispatching to the ones we support.
///
/// This is required due to the "can't turn into object" problem, which we encounter for this trait
/// (due to using async traits and function level type arguments). The only alternative would be
/// to propagate the specific type up to the root level. However, that would also mean that actix
/// handlers would be required to know about that full type to extract it as application
/// data.
///
/// NOTE: Right now we only have one type (filesystem), but the goal is to have an additional one
/// soon (e.g. S3)
#[derive(Clone, Debug)]
pub enum DispatchBackend {
    Filesystem(FileSystemBackend),
}

impl StorageBackend for DispatchBackend {
    type Error = anyhow::Error;

    async fn store<E, S>(&self, stream: S) -> Result<Output<Sha256>, StoreError<E, Self::Error>>
    where
        E: Debug,
        S: Stream<Item = Result<Bytes, E>>,
    {
        match self {
            Self::Filesystem(backend) => backend.store(stream).await.map_err(Self::map_err),
        }
    }

    async fn retrieve(
        self,
        hash_key: HashKey,
    ) -> Result<Option<impl Stream<Item = Result<Bytes, Self::Error>>>, Self::Error>
    where
        Self: Sized,
    {
        match self {
            Self::Filesystem(backend) => backend
                .retrieve(hash_key)
                .await
                .map(|stream| stream.map(|stream| stream.map_err(anyhow::Error::from)))
                .map_err(anyhow::Error::from),
        }
    }
}

impl DispatchBackend {
    /// convert any backend error to [`anyhow::Error`].
    fn map_err<S, B>(error: StoreError<S, B>) -> StoreError<S, anyhow::Error>
    where
        S: Debug,
        B: std::error::Error + Send + Sync + 'static,
    {
        match error {
            StoreError::Stream(err) => StoreError::Stream(err),
            StoreError::Backend(err) => StoreError::Backend(anyhow::Error::from(err)),
        }
    }
}

impl From<FileSystemBackend> for DispatchBackend {
    fn from(value: FileSystemBackend) -> Self {
        Self::Filesystem(value)
    }
}
