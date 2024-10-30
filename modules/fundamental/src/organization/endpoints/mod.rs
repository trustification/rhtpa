#[cfg(test)]
mod test;

use crate::organization::{
    model::{OrganizationDetails, OrganizationSummary},
    service::OrganizationService,
};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::{
    db::{query::Query, Database},
    model::Paginated,
};
use utoipa::OpenApi;
use uuid::Uuid;

pub const CONTEXT_PATH: &str = "/v1/organization";

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = OrganizationService::new(db);
    config.service(
        utoipa_actix_web::scope(CONTEXT_PATH)
            .app_data(web::Data::new(service))
            .service(all)
            .service(get),
    );
}

#[derive(OpenApi)]
#[openapi(paths(all, get), tags())]
pub struct ApiDoc;

#[utoipa::path(
    tag = "organization",
    operation_id = "listOrganizations",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching organizations", body = OrganizationSummary),
    ),
)]
#[get("")]
/// List organizations
pub async fn all(
    state: web::Data<OrganizationService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_organizations(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "organization",
    operation_id = "getOrganization",
    params(
        ("id", Path, description = "Opaque ID of the organization")
    ),
    responses(
        (status = 200, description = "Matching organization", body = OrganizationDetails),
        (status = 404, description = "Matching organization not found"),
    ),
)]
#[get("/{id}")]
/// Retrieve organization details
pub async fn get(
    state: web::Data<OrganizationService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    let fetched = state.fetch_organization(*id, ()).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
