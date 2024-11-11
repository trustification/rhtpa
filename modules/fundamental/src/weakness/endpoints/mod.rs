use crate::{license::model::LicenseSummary, weakness::service::WeaknessService};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{authorizer::Require, ReadWeakness};
use trustify_common::{
    db::{query::Query, Database},
    model::{Paginated, PaginatedResults},
};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let weakness_service = WeaknessService::new(db);

    config
        .app_data(web::Data::new(weakness_service))
        .service(list_weaknesses)
        .service(get_weakness);
}

#[utoipa::path(
    tag = "weakness",
    operation_id = "listWeaknesses",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching weaknesses", body = PaginatedResults<LicenseSummary>),
    ),
)]
#[get("/v1/weakness")]
/// List weaknesses
pub async fn list_weaknesses(
    state: web::Data<WeaknessService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadWeakness>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.list_weaknesses(search, paginated).await?))
}

#[utoipa::path(
    tag = "weakness",
    operation_id = "getWeakness",
    responses(
        (status = 200, description = "The weakness", body = LicenseSummary),
    ),
)]
#[get("/v1/weakness/{id}")]
/// Retrieve weakness details
pub async fn get_weakness(
    state: web::Data<WeaknessService>,
    id: web::Path<String>,
    _: Require<ReadWeakness>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.get_weakness(&id).await?))
}

#[cfg(test)]
mod test;
