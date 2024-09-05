use crate::license::service::LicenseService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    tag = "spdx license",
    operation_id = "listSpdxLicenses",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching licenses", body = PaginatedSpdxLicenseSummary),
    ),
)]
#[get("/v1/license/spdx/license")]
/// List SPDX licenses
pub async fn list_spdx_licenses(
    state: web::Data<LicenseService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    let result = state.list_spdx_licenses(search, paginated).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "spdx license",
    operation_id = "getSpdxLicense",
    context_path = "/api",
    responses(
        (status = 200, description = "SPDX license details", body = SpdxLicenseDetails),
    ),
)]
#[get("/v1/license/spdx/license/{id}")]
/// Get SPDX license details
pub async fn get_spdx_license(
    state: web::Data<LicenseService>,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    if let Some(result) = state.get_spdx_license(&id).await? {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
