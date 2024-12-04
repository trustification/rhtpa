use crate::{
    ai::service::tools::{self, input_description},
    vulnerability::service::VulnerabilityService,
};
use async_trait::async_trait;
use langchain_rust::tools::Tool;
use serde::Serialize;
use serde_json::Value;
use std::{error::Error, fmt::Write};
use time::OffsetDateTime;
use trustify_common::{
    db::{query::Query, Database},
    purl::Purl,
};
use trustify_module_ingestor::common::Deprecation;

pub struct CVEInfo {
    pub db: Database,
    pub service: VulnerabilityService,
}

impl CVEInfo {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            service: VulnerabilityService::new(),
        }
    }
}

#[async_trait]
impl Tool for CVEInfo {
    fn name(&self) -> String {
        String::from("cve-info")
    }

    fn description(&self) -> String {
        String::from(
            r##"
This tool can be used to get information about a Vulnerability.
A Vulnerability is also known as a CVE.

Vulnerabilities are security issues that may affect software packages.
Vulnerabilities may affect multiple packages.

Vulnerability are identified by their CVE Identifier.
"##
            .trim(),
        )
    }

    fn parameters(&self) -> Value {
        input_description(
            r#"
The input should be the partial or full name of the Vulnerability to search for.  Example:
* CVE-2014-0160

        "#,
        )
    }

    async fn run(&self, input: Value) -> Result<String, Box<dyn Error>> {
        let service = &self.service;

        let input = input
            .as_str()
            .ok_or("Input should be a string")?
            .to_string();

        let item = match service
            .fetch_vulnerability(input.as_str(), Deprecation::Ignore, &self.db)
            .await?
        {
            Some(v) => v,
            None => {
                // search for possible matches
                let results = service
                    .fetch_vulnerabilities(
                        Query {
                            q: input.clone(),
                            ..Default::default()
                        },
                        Default::default(),
                        Deprecation::Ignore,
                        &self.db,
                    )
                    .await?;

                if results.items.is_empty() {
                    return Ok(format!("Vulnerability '{input}' not found"));
                }

                // let the caller know what the possible matches are
                if results.items.len() > 1 {
                    #[derive(Serialize)]
                    struct Item {
                        identifier: String,
                        name: Option<String>,
                    }

                    let json = tools::paginated_to_json(results, |item| Item {
                        identifier: item.head.identifier.clone(),
                        name: item.head.title.clone(),
                    })?;
                    return Ok(format!("There are multiple that match:\n\n{}", json));
                }

                // let's show the details for the one that matched.
                if let Some(v) = service
                    .fetch_vulnerability(
                        results.items[0].head.identifier.as_str(),
                        Deprecation::Ignore,
                        &self.db,
                    )
                    .await?
                {
                    v
                } else {
                    return Ok(format!("Vulnerability '{input}' not found"));
                }
            }
        };

        #[derive(Serialize)]
        struct Item {
            identifier: String,
            title: Option<String>,
            description: Option<String>,
            severity: Option<f64>,
            score: Option<f64>,
            #[serde(with = "time::serde::rfc3339::option")]
            released: Option<OffsetDateTime>,
            affected_packages: Vec<Package>,
        }
        #[derive(Serialize)]
        struct Package {
            name: Purl,
            version: String,
        }

        let affected_packages = item
            .advisories
            .iter()
            .flat_map(|v| {
                v.purls
                    .get("affected")
                    .into_iter()
                    .flatten()
                    .map(|v| Package {
                        name: v.base_purl.purl.clone(),
                        version: v.version.clone(),
                    })
            })
            .collect();
        let json = tools::to_json(&Item {
            identifier: item.head.identifier.clone(),
            title: item.head.title.clone(),
            description: item.head.description.clone(),
            severity: item.average_score,
            score: item.average_score,
            released: item.head.released,
            affected_packages,
        })?;

        let mut result = "".to_string();
        if item.head.identifier != input {
            writeln!(result, "There is one match, but it had a different identifier.  Inform the user that that you are providing information on: {}\n", item.head.identifier)?;
        }
        writeln!(result, "{}", json)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::service::test::ingest_fixtures;
    use crate::ai::service::tools::tests::assert_tool_contains;
    use std::rc::Rc;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn cve_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ingest_fixtures(ctx).await?;
        let tool = Rc::new(CVEInfo::new(ctx.db.clone()));
        assert_tool_contains(
            tool.clone(),
            "CVE-2021-32714",
            r#"
{
  "identifier": "CVE-2021-32714",
  "title": "Integer Overflow in Chunked Transfer-Encoding",
  "description": "hyper is an HTTP library for Rust. In versions prior to 0.14.10, hyper's HTTP server and client code had a flaw that could trigger an integer overflow when decoding chunk sizes that are too big. This allows possible data loss, or if combined with an upstream HTTP proxy that allows chunk sizes larger than hyper does, can result in \"request smuggling\" or \"desync attacks.\" The vulnerability is patched in version 0.14.10. Two possible workarounds exist. One may reject requests manually that contain a `Transfer-Encoding` header or ensure any upstream proxy rejects `Transfer-Encoding` chunk sizes greater than what fits in 64-bit unsigned integers.",
  "severity": 9.1,
  "score": 9.1,
  "released": null,
  "affected_packages": [
    {
      "name": "pkg:cargo/hyper",
      "version": "[0.0.0-0,0.14.10)"
    }
  ]
}
"#).await
    }
}
