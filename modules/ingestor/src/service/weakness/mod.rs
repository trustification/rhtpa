use crate::{graph::Graph, model::IngestResult, service::Error};
use hex::ToHex;
use roxmltree::{Document, Node};
use sea_orm::{EntityTrait, Iterable, Set, TransactionTrait};
use sea_query::OnConflict;
use std::str::from_utf8;
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, hashing::Digests, id::Id};
use trustify_entity::{labels::Labels, weakness};

pub struct CweCatalogLoader<'d> {
    graph: &'d Graph,
}

impl<'d> CweCatalogLoader<'d> {
    pub fn new(graph: &'d Graph) -> Self {
        Self { graph }
    }

    #[instrument(skip(self, buffer), ret)]
    pub async fn load_bytes(
        &self,
        labels: Labels,
        buffer: &[u8],
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let xml = from_utf8(buffer)?;

        let document = Document::parse(xml)?;

        self.load(labels, &document, digests).await
    }

    #[instrument(skip(self, doc), ret)]
    pub async fn load<'x>(
        &self,
        _labels: Labels,
        doc: &Document<'x>,
        digests: &Digests,
    ) -> Result<IngestResult, Error> {
        let root = doc.root();

        let catalog = root.first_element_child();
        if let Some(catalog) = catalog {
            let weaknesses = catalog.first_element_child();
            let mut batch = Vec::new();

            if let Some(weaknesses) = weaknesses {
                let tx = self.graph.db.begin().await?;
                for weakness in weaknesses.children() {
                    if weakness.is_element() {
                        let mut child_of = Vec::new();
                        let mut parent_of = Vec::new();
                        let mut starts_with = Vec::new();
                        let mut can_follow = Vec::new();
                        let mut can_precede = Vec::new();
                        let mut required_by = Vec::new();
                        let mut requires = Vec::new();
                        let mut can_also_be = Vec::new();
                        let mut peer_of = Vec::new();

                        if let Some(id) = weakness.attribute("ID").map(|id| format!("CWE-{id}")) {
                            let mut description = None;
                            let mut extended_description = None;

                            if let Some(description_node) =
                                weakness.children().find(|e| e.has_tag_name("Description"))
                            {
                                description = description_node.text().map(|e| e.to_string());
                            }

                            if let Some(extended_description_node) = weakness
                                .children()
                                .find(|e| e.has_tag_name("Extended_Description"))
                            {
                                extended_description
                                    .replace(gather_content(&extended_description_node));
                            }

                            if let Some(related_weaknesses) = weakness
                                .children()
                                .find(|e| e.has_tag_name("Related_Weaknesses"))
                            {
                                for related in related_weaknesses
                                    .children()
                                    .filter(|e| e.has_tag_name("Related_Weakness"))
                                {
                                    if let Some(target) = related.attribute("CWE_ID") {
                                        if let Some(nature) = related.attribute("Nature") {
                                            if let Some(dest) = match nature {
                                                "ChildOf" => Some(&mut child_of),
                                                "ParentOf" => Some(&mut parent_of),
                                                "StartsWith" => Some(&mut starts_with),
                                                "CanFollow" => Some(&mut can_follow),
                                                "CanPrecede" => Some(&mut can_precede),
                                                "RequiredBy" => Some(&mut required_by),
                                                "Requires" => Some(&mut requires),
                                                "CanAlsoBe" => Some(&mut can_also_be),
                                                "PeerOf" => Some(&mut peer_of),
                                                _ => None,
                                            } {
                                                dest.push(target.to_string());
                                            }
                                        }
                                    }
                                }
                            }

                            batch.push(weakness::ActiveModel {
                                id: Set(id),
                                description: Set(description),
                                extended_description: Set(extended_description),
                                child_of: Set(normalize(child_of)),
                                parent_of: Set(normalize(parent_of)),
                                starts_with: Set(normalize(starts_with)),
                                can_follow: Set(normalize(can_follow)),
                                can_precede: Set(normalize(can_precede)),
                                required_by: Set(normalize(required_by)),
                                requires: Set(normalize(requires)),
                                can_also_be: Set(normalize(can_also_be)),
                                peer_of: Set(normalize(peer_of)),
                            });
                        }
                    }
                }

                for chunk in &batch.chunked() {
                    weakness::Entity::insert_many(chunk)
                        .on_conflict(
                            OnConflict::column(weakness::Column::Id)
                                .update_columns(weakness::Column::iter())
                                .to_owned(),
                        )
                        .exec(&tx)
                        .await?;
                }

                tx.commit().await?;
            }
        }

        Ok(IngestResult {
            id: Id::Sha512(digests.sha512.encode_hex()),
            document_id: "CWE".to_string(),
            warnings: vec![],
        })
    }
}

fn normalize(vec: Vec<String>) -> Option<Vec<String>> {
    if vec.is_empty() {
        None
    } else {
        Some(canonicalize(vec))
    }
}

fn canonicalize(vec: Vec<String>) -> Vec<String> {
    vec.iter().map(|e| format!("CWE-{e}")).collect()
}

fn gather_content(node: &Node) -> String {
    let mut dest = String::new();

    let children = node.children();

    for child in children {
        gather_content_inner(&child, &mut dest);
    }

    let dest = dest.trim().to_string();

    dest
}

fn gather_content_inner(node: &Node, dest: &mut String) {
    if node.is_element() {
        dest.push_str(&format!("<{}>", node.tag_name().name()));
        for child in node.children() {
            gather_content_inner(&child, dest);
        }
        dest.push_str(&format!("</{}>", node.tag_name().name()));
    } else if node.is_text() {
        if let Some(text) = node.text() {
            dest.push_str(text);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::graph::Graph;
    use crate::service::weakness::CweCatalogLoader;
    use roxmltree::Document;
    use std::io::Read;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::hashing::HashingRead;
    use trustify_entity::labels::Labels;
    use trustify_test_context::document_read;
    use trustify_test_context::TrustifyContext;
    use zip::ZipArchive;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let graph = Graph::new(ctx.db.clone());
        let loader = CweCatalogLoader::new(&graph);

        let zip = document_read("cwec_latest.xml.zip").await?;

        let mut archive = ZipArchive::new(zip)?;

        let entry = archive.by_index(0)?;

        let mut hashing = HashingRead::new(entry);
        let mut xml = String::new();
        hashing.read_to_string(&mut xml)?;
        let digests = hashing.finish()?;
        let doc = Document::parse(&xml)?;

        // should work twice without error/conflict.
        loader.load(Labels::default(), &doc, &digests).await?;
        loader.load(Labels::default(), &doc, &digests).await?;

        Ok(())
    }
}
