pub mod common;
pub mod csaf;
pub mod osv;
pub mod report;
pub mod sbom;

use crate::{
    model::{Importer, ImporterConfiguration},
    server::report::{Report, ScannerError},
    service::ImporterService,
};
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::MissedTickBehavior;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// run the importer loop
pub async fn importer(
    db: Database,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    Server {
        db,
        storage,
        working_dir,
    }
    .run()
    .await
}

#[derive(Clone, Debug)]
pub struct RunOutput {
    pub report: Report,
    pub continuation: Option<serde_json::Value>,
}

impl From<Report> for RunOutput {
    fn from(report: Report) -> Self {
        Self {
            report,
            continuation: None,
        }
    }
}

struct Server {
    db: Database,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
}

impl Server {
    #[instrument(skip_all, err)]
    async fn run(&self) -> anyhow::Result<()> {
        let service = ImporterService::new(self.db.clone());

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            log::debug!("checking importers");

            let importers = service.list().await?;
            for importer in importers {
                // FIXME: could add that to the query/list operation
                if importer.data.configuration.disabled || can_wait(&importer) {
                    continue;
                }

                log::debug!("  {}: {:?}", importer.name, importer.data.configuration);

                service.update_start(&importer.name, None).await?;

                // record timestamp before processing, so that we can use it as "since" marker
                let last_run = OffsetDateTime::now_utc();

                log::info!("Starting run: {}", importer.name);

                let (last_error, report, continuation) = match self
                    .run_once(
                        importer.data.configuration,
                        importer.data.last_run,
                        importer.data.continuation,
                    )
                    .await
                {
                    Ok(RunOutput {
                        report,
                        continuation,
                    }) => (None, Some(report), continuation),
                    Err(ScannerError::Normal {
                        err,
                        output:
                            RunOutput {
                                report,
                                continuation,
                            },
                    }) => (Some(err.to_string()), Some(report), continuation),
                    Err(ScannerError::Critical(err)) => (Some(err.to_string()), None, None),
                };

                log::info!("Import run complete: {last_error:?}");

                service
                    .update_finish(
                        &importer.name,
                        None,
                        last_run,
                        last_error,
                        continuation,
                        report.and_then(|report| serde_json::to_value(report).ok()),
                    )
                    .await?;
            }
        }
    }

    #[instrument(skip_all, fields(), err, ret)]
    async fn run_once(
        &self,
        configuration: ImporterConfiguration,
        last_run: Option<OffsetDateTime>,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let last_run = last_run.map(|t| t.into());

        match configuration {
            ImporterConfiguration::Sbom(sbom) => self.run_once_sbom(sbom, last_run).await,
            ImporterConfiguration::Csaf(csaf) => self.run_once_csaf(csaf, last_run).await,
            ImporterConfiguration::Osv(osv) => self.run_once_osv(osv, continuation).await,
        }
    }
}

/// check if we need to run or skip the importer
fn can_wait(importer: &Importer) -> bool {
    let Some(last) = importer.data.last_run else {
        return false;
    };

    (OffsetDateTime::now_utc() - last) < importer.data.configuration.period
}
