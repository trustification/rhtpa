//! Support for a *fully-qualified* package.

use crate::graph::{error::Error, purl::package_version::PackageVersionContext, sbom::SbomContext};
use sea_orm::ConnectionTrait;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};
use trustify_common::purl::Purl;
use trustify_entity::{self as entity, qualified_purl};

#[derive(Clone)]
pub struct QualifiedPackageContext<'g> {
    pub package_version: PackageVersionContext<'g>,
    pub qualified_package: entity::qualified_purl::Model,
}

impl PartialEq for QualifiedPackageContext<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.qualified_package.eq(&other.qualified_package)
    }
}

impl Eq for QualifiedPackageContext<'_> {}

impl Hash for QualifiedPackageContext<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.qualified_package.id.as_bytes());
    }
}

impl Debug for QualifiedPackageContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.qualified_package.fmt(f)
    }
}

impl<'g> From<QualifiedPackageContext<'g>> for Purl {
    fn from(value: QualifiedPackageContext<'g>) -> Self {
        Self {
            ty: value.package_version.package.base_purl.r#type,
            namespace: value.package_version.package.base_purl.namespace,
            name: value.package_version.package.base_purl.name,
            version: Some(value.package_version.package_version.version),
            qualifiers: BTreeMap::from_iter(value.qualified_package.qualifiers.0),
        }
    }
}

impl<'g> QualifiedPackageContext<'g> {
    pub fn new(
        package_version: &PackageVersionContext<'g>,
        qualified_package: qualified_purl::Model,
    ) -> Self {
        Self {
            package_version: package_version.clone(),
            qualified_package,
        }
    }
    pub async fn sboms_containing<C: ConnectionTrait>(
        &self,
        _connection: &C,
    ) -> Result<Vec<SbomContext>, Error> {
        /*
        Ok(entity::sbom::Entity::find()
            .join(
                JoinType::Join,
                entity::sbom_contains_package::Relation::Sbom.def().rev(),
            )
            .filter(
                entity::sbom_contains_package::Column::QualifiedPackageId
                    .eq(self.qualified_package.id),
            )
            .all(&self.package_version.package.fetch.connection(tx))
            .await?
            .drain(0..)
            .map(|sbom| (&self.package_version.package.fetch, sbom).into())
            .collect())

         */
        todo!()
    }
}
