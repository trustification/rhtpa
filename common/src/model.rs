mod bytesize;
pub use bytesize::*;

use crate::db::limiter::Limiter;
use sea_orm::{ConnectionTrait, DbErr, SelectorTrait};
use std::cmp::min;
use std::marker::PhantomData;
use utoipa::{IntoParams, ToSchema};

/// A struct wrapping an item with a revision.
///
/// If the revision should not be part of the payload, but e.g. an HTTP header (like `ETag`), this
/// struct can help carrying both pieces.
// NOTE: This struct must be synced with the version in the [`revisioned`] macro below.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Revisioned<T> {
    /// The actual value
    pub value: T,
    /// The revision.
    ///
    /// An opaque string that should have no meaning to the user, only to the backend.
    pub revision: String,
}

#[derive(
    IntoParams, Copy, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct Paginated {
    /// The first item to return, skipping all that come before it.
    ///
    /// NOTE: The order of items is defined by the API being called.
    #[serde(default)]
    pub offset: u64,
    /// The maximum number of entries to return.
    ///
    /// Zero means: no limit
    #[serde(default = "default::limit")]
    pub limit: u64,
}

impl Paginated {
    pub fn paginate_array<T: Clone>(&self, vec: &[T]) -> PaginatedResults<T> {
        // trying to start past the end of the vec
        if self.offset as usize > vec.len() {
            return PaginatedResults {
                items: vec![],
                total: vec.len() as u64,
            };
        }

        if self.limit == 0 {
            return PaginatedResults {
                items: Vec::from(&vec[self.offset as usize..]),
                total: vec.len() as u64,
            };
        }

        let end = min(self.offset as usize + self.limit as usize, vec.len());

        PaginatedResults {
            items: Vec::from(&vec[self.offset as usize..end]),
            total: vec.len() as u64,
        }
    }
}

mod default {
    pub(super) const fn limit() -> u64 {
        25
    }
}

// NOTE: This struct must be aligned with the struct in the [`paginated`] macro below.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<R> {
    pub items: Vec<R>,
    pub total: u64,
}

impl<R> PaginatedResults<R> {
    /// Create a new paginated result
    pub async fn new<C, S1, S2>(
        limiter: Limiter<'_, C, S1, S2>,
    ) -> Result<PaginatedResults<S1::Item>, DbErr>
    where
        C: ConnectionTrait,
        S1: SelectorTrait,
        S2: SelectorTrait,
    {
        let total = limiter.total().await?;
        let results = limiter.fetch().await?;

        Ok(PaginatedResults {
            items: results,
            total,
        })
    }

    pub fn map<O, F: Fn(R) -> O>(mut self, f: F) -> PaginatedResults<O> {
        PaginatedResults {
            items: self.items.drain(..).map(f).collect(),
            total: self.total,
        }
    }
}

#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct BinaryData(PhantomData<Vec<u8>>);

#[cfg(test)]
mod test {
    use crate::model::Paginated;

    #[test_log::test(test)]
    fn paginated_vec() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let paginated = Paginated {
            offset: 0,
            limit: 0,
        }
        .paginate_array(&data);

        assert_eq!(10, paginated.total);
        assert_eq!(10, paginated.items.len());

        let paginated = Paginated {
            offset: 0,
            limit: 5,
        }
        .paginate_array(&data);

        assert_eq!(10, paginated.total);
        assert_eq!(5, paginated.items.len());

        let paginated = Paginated {
            offset: 5,
            limit: 0,
        }
        .paginate_array(&data);

        assert_eq!(10, paginated.total);
        assert_eq!(5, paginated.items.len());

        let paginated = Paginated {
            offset: 12,
            limit: 0,
        }
        .paginate_array(&data);

        assert_eq!(10, paginated.total);
        assert_eq!(0, paginated.items.len());
    }
}
