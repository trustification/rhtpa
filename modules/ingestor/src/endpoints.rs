use crate::{
    graph::Graph,
    service::{Error, IngestorService},
};
use actix_web::{post, web, HttpResponse, Responder};
use trustify_auth::{authorizer::Require, UploadDataset};
use trustify_common::{db::Database, model::BinaryData};
use trustify_entity::labels::Labels;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::IntoParams;

/// mount the "ingestor" module
pub fn configure(
    svc: &mut utoipa_actix_web::service_config::ServiceConfig,
    config: Config,
    db: Database,
    storage: impl Into<DispatchBackend>,
) {
    let ingestor_service = IngestorService::new(Graph::new(db.clone()), storage);

    svc.app_data(web::Data::new(ingestor_service))
        .app_data(web::Data::new(config))
        .service(upload_dataset);
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    /// Limit of a single content entry (after decompression).
    pub dataset_entry_limit: usize,
}

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
}

#[utoipa::path(
    tag = "dataset",
    operation_id = "uploadDataset",
    request_body = inline(BinaryData),
    params(UploadParams),
    responses(
        (status = 201, description = "Uploaded the dataset"),
        (status = 400, description = "The file could not be parsed as an dataset"),
    )
)]
#[post("/v1/dataset")]
/// Upload a new dataset
pub async fn upload_dataset(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    web::Query(UploadParams { labels }): web::Query<UploadParams>,
    bytes: web::Bytes,
    _: Require<UploadDataset>,
) -> Result<impl Responder, Error> {
    let result = service
        .ingest_dataset(&bytes, labels, config.dataset_entry_limit)
        .await?;
    Ok(HttpResponse::Created().json(result))
}
