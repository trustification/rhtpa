use super::service::{Error, ImporterService, PatchError};
use crate::model::{Importer, ImporterConfiguration, PaginatedImporterReport, RevisionedImporter};
use actix_web::{
    delete, get,
    guard::{self, Guard, GuardContext},
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web, HttpResponse, Responder,
};
use std::convert::Infallible;
use trustify_common::{
    db::Database,
    model::{Paginated, Revisioned},
};
use utoipa::OpenApi;

/// mount the "importer" module
pub fn configure(svc: &mut web::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(ImporterService::new(db)));
    svc.service(
        web::scope("/v1/importer")
            .service(list)
            .service(create)
            .service(read)
            .service(update)
            .service(patch_json_merge)
            .service(delete)
            .service(get_reports)
            .service(set_enabled)
            .service(force),
    );
}

#[derive(OpenApi)]
#[openapi(
    paths(
        create,
        delete,
        force,
        get_reports,
        list,
        patch_json_merge,
        read,
        set_enabled,
        update,
    ),
    components(schemas(
        crate::model::ClearlyDefinedCurationImporter,
        crate::model::ClearlyDefinedImporter,
        crate::model::ClearlyDefinedPackageType,
        crate::model::CommonImporter,
        crate::model::CsafImporter,
        crate::model::CveImporter,
        crate::model::CweImporter,
        crate::model::Importer,
        crate::model::ImporterConfiguration,
        crate::model::ImporterData,
        crate::model::ImporterReport,
        crate::model::OsvImporter,
        crate::model::PaginatedImporterReport,
        crate::model::Progress,
        crate::model::RevisionedImporter,
        crate::model::SbomImporter,
        crate::model::State,
        trustify_common::model::BinaryByteSize,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "listImporters",
    responses(
        (status = 200, description = "List importer configurations", body = [Importer])
    )
)]
#[get("")]
/// List importer configurations
async fn list(service: web::Data<ImporterService>) -> Result<impl Responder, Error> {
    Ok(web::Json(service.list().await?))
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "createImporter",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "An importer with that name already exists")
    )
)]
#[post("/{name}")]
/// Create a new importer configuration
async fn create(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
) -> Result<impl Responder, Error> {
    service.create(name.into_inner(), configuration).await?;
    Ok(HttpResponse::Created().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "getImporter",
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 200, description = "Retrieved importer configuration",
            body = RevisionedImporter,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 404, description = "An importer with that name could not be found")
    )
)]
#[get("/{name}")]
/// Get an importer configuration
async fn read(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
) -> Result<Option<impl Responder>, Error> {
    Ok(service
        .read(&name)
        .await?
        .map(|Revisioned { value, revision }| {
            HttpResponse::Ok()
                .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
                .json(value)
        }))
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "updateImporter",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the importer configuration"),
        (status = 409, description = "An importer with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/{name}")]
/// Update an existing importer configuration
async fn update(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .update_configuration(&name, revision, configuration)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "patchImporter",
    request_body(
        content = serde_json::Value,
        content_type = guards::JSON_MERGE_CONTENT_TYPE,
    ),
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "An importer with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[patch("/{name}", guard = "guards::json_merge")]
/// Update an existing importer configuration
async fn patch_json_merge(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(patch): web::Json<serde_json::Value>,
) -> Result<impl Responder, PatchError<serde_json::Error>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_configuration(&name, revision, |config| {
            let mut json = serde_json::to_value(&config)?;
            json_merge_patch::json_merge_patch(&mut json, &patch);
            serde_json::from_value(json)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "enableImporter",
    request_body = bool,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the enable state"),
        (status = 404, description = "An importer with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/{name}/enabled")]
/// Update an existing importer configuration
async fn set_enabled(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(state): web::Json<bool>,
) -> Result<impl Responder, PatchError<Infallible>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_configuration(&name, revision, |mut configuration| {
            configuration.disabled = !state;
            Ok(configuration)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "forceRunImporter",
    request_body = bool,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the state"),
        (status = 404, description = "An importer with that name does not exist"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[post("/{name}/force")]
/// Force an importer to run as soon as possible
async fn force(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service.reset(&name, revision).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "deleteImporter",
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 201, description = "Delete the importer configuration"),
    )
)]
#[delete("/{name}")]
/// Delete an importer configuration
async fn delete(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    Ok(match service.delete(&name, revision).await? {
        true => HttpResponse::NoContent().finish(),
        false => HttpResponse::NoContent().finish(),
    })
}

#[utoipa::path(
    context_path = "/api/v1/importer",
    tag = "importer",
    operation_id = "listImporterReports",
    responses(
        (status = 200, description = "Retrieved importer reports", body = PaginatedImporterReport),
    )
)]
#[get("/{name}/report")]
/// Get reports for an importer
async fn get_reports(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(service.get_reports(&name, paginated).await?))
}

mod guards {
    use super::*;

    pub const JSON_MERGE_CONTENT_TYPE: &str = "application/merge-patch+json";

    pub fn json_merge(ctx: &GuardContext) -> bool {
        guard::Header("content-type", JSON_MERGE_CONTENT_TYPE).check(ctx)
    }
}
