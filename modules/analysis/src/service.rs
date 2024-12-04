use crate::{
    model::{AnalysisStatus, AncNode, AncestorSummary, DepNode, DepSummary, GraphMap, PackageNode},
    Error,
};
use petgraph::{
    algo::is_cyclic_directed,
    graph::{Graph, NodeIndex},
    visit::{NodeIndexable, VisitMap, Visitable},
    Direction,
};
use sea_orm::{
    prelude::ConnectionTrait, ColumnTrait, DatabaseBackend, DbErr, EntityOrSelect, EntityTrait,
    QueryFilter, QueryOrder, QueryResult, QuerySelect, QueryTrait, Statement,
};
use sea_query::Order;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use tracing::instrument;
use trustify_common::{
    db::query::{Filtering, Query, Value},
    model::{Paginated, PaginatedResults},
    purl::Purl,
};
use trustify_entity::{relationship::Relationship, sbom, sbom_node};
use uuid::Uuid;

#[derive(Default)]
pub struct AnalysisService {}

pub fn dep_nodes(
    graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
    visited: &mut HashSet<NodeIndex>,
) -> Vec<DepNode> {
    let mut depnodes = Vec::new();
    fn dfs(
        graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
        node: NodeIndex,
        depnodes: &mut Vec<DepNode>,
        visited: &mut HashSet<NodeIndex>,
    ) {
        if visited.contains(&node) {
            return;
        }
        visited.insert(node);
        for neighbor in graph.neighbors_directed(node, Direction::Incoming) {
            if let Some(dep_packagenode) = graph.node_weight(neighbor).cloned() {
                // Attempt to find the edge and get the relationship in a more elegant way
                if let Some(relationship) = graph
                    .find_edge(neighbor, node)
                    .and_then(|edge_index| graph.edge_weight(edge_index))
                {
                    let dep_node = DepNode {
                        sbom_id: dep_packagenode.sbom_id,
                        node_id: dep_packagenode.node_id,
                        relationship: relationship.to_string(),
                        purl: dep_packagenode.purl.to_string(),
                        name: dep_packagenode.name.to_string(),
                        version: dep_packagenode.version.to_string(),
                        deps: dep_nodes(graph, neighbor, visited),
                    };
                    depnodes.push(dep_node);
                    dfs(graph, neighbor, depnodes, visited);
                }
            } else {
                log::warn!(
                    "Processing descendants node weight for neighbor {:?} not found",
                    neighbor
                );
            }
        }
    }
    dfs(graph, node, &mut depnodes, visited);
    depnodes
}

pub fn ancestor_nodes(
    graph: &Graph<PackageNode, Relationship, petgraph::Directed>,
    node: NodeIndex,
) -> Vec<AncNode> {
    let mut discovered = graph.visit_map();
    let mut ancestor_nodes = Vec::new();
    let mut stack = Vec::new();

    stack.push(graph.from_index(node.index()));

    while let Some(node) = stack.pop() {
        if discovered.visit(node) {
            for succ in graph.neighbors_directed(node, Direction::Outgoing) {
                if !discovered.is_visited(&succ) {
                    if let Some(anc_packagenode) = graph.node_weight(succ).cloned() {
                        if let Some(edge) = graph.find_edge(node, succ) {
                            if let Some(relationship) = graph.edge_weight(edge) {
                                let anc_node = AncNode {
                                    sbom_id: anc_packagenode.sbom_id,
                                    node_id: anc_packagenode.node_id,
                                    relationship: relationship.to_string(),
                                    purl: anc_packagenode.purl,
                                    name: anc_packagenode.name,
                                    version: anc_packagenode.version,
                                };
                                ancestor_nodes.push(anc_node);
                                stack.push(succ);
                            } else {
                                log::warn!(
                                    "Edge weight not found for edge between {:?} and {:?}",
                                    node,
                                    succ
                                );
                            }
                        } else {
                            log::warn!("Edge not found between {:?} and {:?}", node, succ);
                        }
                    } else {
                        log::warn!("Processing ancestors, node value for {:?} not found", succ);
                    }
                }
            }
            if graph.neighbors_directed(node, Direction::Outgoing).count() == 0 {
                continue; // we are at the root
            }
        }
    }
    ancestor_nodes
}

pub async fn get_implicit_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: &str,
) -> Result<Vec<QueryResult>, DbErr> {
    let sql = r#"
        SELECT
             sbom.document_id,
             sbom.sbom_id,
             sbom.published::text,
             get_purl(t1.qualified_purl_id) as purl,
             t1_node.node_id,
             t1_node.name AS node_name,
             t1_version.version AS node_version,
             product.name AS product_name,
             product_version.version AS product_version
        FROM
            sbom
        LEFT JOIN
            product_version ON sbom.sbom_id = product_version.sbom_id
        LEFT JOIN
            product ON product_version.product_id = product.id
        LEFT JOIN
            sbom_node t1_node ON sbom.sbom_id = t1_node.sbom_id
        LEFT JOIN
            package_relates_to_package prtp ON t1_node.node_id = prtp.left_node_id OR t1_node.node_id = prtp.right_node_id
        LEFT JOIN
            sbom_package_purl_ref t1 ON t1_node.node_id = t1.node_id AND t1.sbom_id = sbom.sbom_id
        LEFT JOIN
            sbom_package t1_version ON t1_node.node_id = t1_version.node_id AND t1_version.sbom_id = sbom.sbom_id
        WHERE
            prtp.left_node_id IS NULL AND prtp.right_node_id IS NULL
          AND
            sbom.sbom_id = $1
        "#;

    let uuid = match Uuid::parse_str(distinct_sbom_id) {
        Ok(uuid) => uuid,
        Err(_) => return Err(sea_orm::DbErr::Custom("Invalid SBOM ID".to_string())),
    };
    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [uuid.into()]);
    let results: Vec<QueryResult> = connection.query_all(stmt).await?;

    Ok(results)
}

pub async fn get_relationships<C: ConnectionTrait>(
    connection: &C,
    distinct_sbom_id: &str,
) -> Result<Vec<QueryResult>, DbErr> {
    // Retrieve all SBOM components that have defined relationships
    let sql = r#"
        SELECT
            sbom.document_id,
            sbom.sbom_id,
            sbom.published::text,
            t1.node_id AS left_node_id,
            get_purl(t1.qualified_purl_id) AS left_qualified_purl,
            t1_node.name AS left_node_name,
            t1_version.version AS left_node_version,
            package_relates_to_package.relationship,
            t2.node_id AS right_node_id,
            get_purl(t2.qualified_purl_id) AS right_qualified_purl,
            t2_node.name AS right_node_name,
            t2_version.version AS right_node_version,
            product.name AS product_name,
            product_version.version AS product_version
        FROM
            sbom
        LEFT JOIN
            product_version ON sbom.sbom_id = product_version.sbom_id
        LEFT JOIN
            product ON product_version.product_id = product.id
        LEFT JOIN
            package_relates_to_package ON sbom.sbom_id = package_relates_to_package.sbom_id
        LEFT JOIN
            sbom_package_purl_ref t1 ON sbom.sbom_id = t1.sbom_id AND t1.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_node t1_node ON sbom.sbom_id = t1_node.sbom_id AND t1_node.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_package t1_version ON sbom.sbom_id = t1_version.sbom_id AND t1_version.node_id = package_relates_to_package.left_node_id
        LEFT JOIN
            sbom_package_purl_ref t2 ON sbom.sbom_id = t2.sbom_id AND t2.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            sbom_node t2_node ON sbom.sbom_id = t2_node.sbom_id AND t2_node.node_id = package_relates_to_package.right_node_id
        LEFT JOIN
            sbom_package t2_version ON sbom.sbom_id = t2_version.sbom_id AND t2_version.node_id = package_relates_to_package.right_node_id
        WHERE
            package_relates_to_package.relationship IN (0, 1, 8, 13, 14, 15)
            AND sbom.sbom_id = $1;
        "#;

    let uuid = match Uuid::parse_str(distinct_sbom_id) {
        Ok(uuid) => uuid,
        Err(_) => return Err(sea_orm::DbErr::Custom("Invalid SBOM ID".to_string())),
    };
    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, [uuid.into()]);
    let results: Vec<QueryResult> = connection.query_all(stmt).await?;

    Ok(results)
}

pub async fn load_graphs<C: ConnectionTrait>(connection: &C, distinct_sbom_ids: &Vec<String>) {
    let graph_map = GraphMap::get_instance();
    {
        for distinct_sbom_id in distinct_sbom_ids {
            if !graph_map.read().contains_key(distinct_sbom_id) {
                // lazy load graphs
                let mut g: Graph<PackageNode, Relationship, petgraph::Directed> = Graph::new();
                let mut nodes = HashMap::new();

                let mut describedby_purl: String = Default::default();

                // Set relationships explicitly defined in SBOM
                match get_relationships(connection, &distinct_sbom_id.to_string()).await {
                    Ok(results) => {
                        for row in results {
                            let (
                                sbom_published,
                                document_id,
                                product_name,
                                product_version,
                                left_node_id,
                                left_purl_string,
                                left_node_name,
                                left_node_version,
                                right_node_id,
                                right_purl_string,
                                right_node_name,
                                right_node_version,
                                relationship,
                            ) = {
                                let default_value = "NOVALUE".to_string(); // TODO: this eventually will have different defaults.
                                (
                                    row.try_get("", "published")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "document_id")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_name")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_version")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "left_node_id")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "left_qualified_purl")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "left_node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "left_node_version")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_node_id")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_qualified_purl")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "right_node_version")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "relationship")
                                        .unwrap_or(Relationship::ContainedBy),
                                )
                            };

                            if relationship == Relationship::DescribedBy {
                                // Save for implicit relationships performed later
                                describedby_purl = left_purl_string.clone();
                            } else {
                                let p1 = match nodes.get(&left_purl_string) {
                                    Some(&node_index) => node_index, // already exists
                                    None => {
                                        let new_node = PackageNode {
                                            sbom_id: distinct_sbom_id.clone(),
                                            node_id: left_node_id.clone(),
                                            purl: left_purl_string.clone(),
                                            name: left_node_name.clone(),
                                            version: left_node_version.clone(),
                                            published: sbom_published.clone(),
                                            document_id: document_id.clone(),
                                            product_name: product_name.clone(),
                                            product_version: product_version.clone(),
                                        };
                                        let i = g.add_node(new_node);
                                        nodes.insert(left_purl_string.clone(), i);
                                        i
                                    }
                                };

                                let p2 = match nodes.get(&right_purl_string) {
                                    Some(&node_index) => node_index, // already exists
                                    None => {
                                        let new_node = PackageNode {
                                            sbom_id: distinct_sbom_id.clone(),
                                            node_id: right_node_id.clone(),
                                            purl: right_purl_string.clone(),
                                            name: right_node_name.clone(),
                                            version: right_node_version.clone(),
                                            published: sbom_published.clone(),
                                            document_id: document_id.clone(),
                                            product_name: product_name.clone(),
                                            product_version: product_version.clone(),
                                        };
                                        let i = g.add_node(new_node);
                                        nodes.insert(right_purl_string.clone(), i);
                                        i
                                    }
                                };

                                g.add_edge(p1, p2, relationship);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("Error fetching graph relationships: {}", err);
                    }
                }

                // Set relationships implicitly defined in SBOM
                match get_implicit_relationships(connection, &distinct_sbom_id.to_string()).await {
                    Ok(results) => {
                        for row in results {
                            let (
                                sbom_published,
                                document_id,
                                product_name,
                                product_version,
                                node_id,
                                purl,
                                node_name,
                                node_version,
                            ) = {
                                let default_value = "NOVALUE".to_string(); // TODO: this eventually will have different defaults.
                                (
                                    row.try_get("", "published")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "document_id")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_name")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "product_version")
                                        .unwrap_or_else(|_| default_value.clone()),
                                    row.try_get("", "node_id").unwrap_or(default_value.clone()),
                                    row.try_get("", "purl").unwrap_or(default_value.clone()),
                                    row.try_get("", "node_name")
                                        .unwrap_or(default_value.clone()),
                                    row.try_get("", "node_version")
                                        .unwrap_or(default_value.clone()),
                                )
                            };

                            let p1 = match nodes.get(&purl) {
                                Some(&node_index) => node_index, // already exists
                                None => {
                                    let new_node = PackageNode {
                                        sbom_id: distinct_sbom_id.clone(),
                                        node_id: node_id.clone(),
                                        purl: purl.clone(),
                                        name: node_name.clone(),
                                        version: node_version.clone(),
                                        published: sbom_published.clone(),
                                        document_id: document_id.clone(),
                                        product_name: product_name.clone(),
                                        product_version: product_version.clone(),
                                    };
                                    let i = g.add_node(new_node);
                                    nodes.insert(purl.clone(), i);
                                    i
                                }
                            };
                            if let Some(describedby_node_index) = nodes.get(&describedby_purl) {
                                g.add_edge(p1, *describedby_node_index, Relationship::Undefined);
                            } else {
                                log::warn!("No 'describes' relationship found in {} SBOM, no implicit relationship set.", distinct_sbom_id);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("Error fetching graph relationships: {}", err);
                    }
                }

                graph_map.write().insert(distinct_sbom_id.to_string(), g);
            }
        }
    }
}

impl AnalysisService {
    pub fn new() -> Self {
        let _ = GraphMap::get_instance();
        Self {}
    }

    pub async fn load_graphs<C: ConnectionTrait>(
        &self,
        distinct_sbom_ids: Vec<String>,
        connection: &C,
    ) -> Result<(), Error> {
        load_graphs(connection, &distinct_sbom_ids).await;

        Ok(())
    }
    pub async fn load_all_graphs<C: ConnectionTrait>(&self, connection: &C) -> Result<(), Error> {
        // retrieve all sboms in trustify
        let distinct_sbom_ids = sbom::Entity::find()
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        Ok(())
    }

    pub async fn clear_all_graphs(&self) -> Result<(), Error> {
        let graph_manager = GraphMap::get_instance();
        let mut manager = graph_manager.write();
        manager.clear();
        Ok(())
    }

    pub async fn status<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<AnalysisStatus, Error> {
        let distinct_sbom_ids = sbom::Entity::find()
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?;

        let graph_manager = GraphMap::get_instance();
        let manager = graph_manager.read();
        Ok(AnalysisStatus {
            sbom_count: distinct_sbom_ids.len() as i32,
            graph_count: manager.len() as i32,
        })
    }

    pub async fn query_ancestor_graph(
        component_name: Option<String>,
        component_purl: Option<Purl>,
        query: Option<Query>,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<AncestorSummary> {
        let mut components = Vec::new();
        let graph_manager = GraphMap::get_instance();
        {
            // RwLock for reading hashmap<graph>
            let graph_read_guard = graph_manager.read();
            for distinct_sbom_id in &distinct_sbom_ids {
                if let Some(graph) = graph_read_guard.get(distinct_sbom_id.to_string().as_str()) {
                    if is_cyclic_directed(graph) {
                        log::warn!(
                            "analysis graph of sbom {} has circular references!",
                            distinct_sbom_id
                        );
                    }

                    let mut visited = HashSet::new();

                    // Iterate over matching node indices and process them directly
                    graph
                        .node_indices()
                        .filter(|&i| {
                            if let Some(component_name) = &component_name {
                                graph
                                    .node_weight(i)
                                    .map(|node| node.name.eq(component_name))
                                    .unwrap_or(false)
                            } else if let Some(component_purl) = component_purl.clone() {
                                if let Some(node) = graph.node_weight(i) {
                                    match Purl::from_str(&node.purl).map_err(Error::Purl) {
                                        Ok(purl) => purl == component_purl,
                                        Err(err) => {
                                            log::warn!(
                                                "Error retrieving purl from analysis graph {}",
                                                err
                                            );
                                            false
                                        }
                                    }
                                } else {
                                    false // Return false if the node does not exist
                                }
                            } else if let Some(query) = &query {
                                graph
                                    .node_weight(i)
                                    .map(|node| {
                                        query.apply(&HashMap::from([
                                            ("sbom_id", Value::String(&node.sbom_id)),
                                            ("node_id", Value::String(&node.node_id)),
                                            ("name", Value::String(&node.name)),
                                            ("version", Value::String(&node.version)),
                                        ]))
                                    })
                                    .unwrap_or(false)
                            } else {
                                false
                            }
                        })
                        .for_each(|node_index| {
                            if !visited.contains(&node_index) {
                                visited.insert(node_index);

                                if let Some(find_match_package_node) = graph.node_weight(node_index)
                                {
                                    log::debug!("matched!");
                                    components.push(AncestorSummary {
                                        sbom_id: find_match_package_node.sbom_id.to_string(),
                                        node_id: find_match_package_node.node_id.to_string(),
                                        purl: find_match_package_node.purl.to_string(),
                                        name: find_match_package_node.name.to_string(),
                                        version: find_match_package_node.version.to_string(),
                                        published: find_match_package_node.published.to_string(),
                                        document_id: find_match_package_node
                                            .document_id
                                            .to_string(),
                                        product_name: find_match_package_node
                                            .product_name
                                            .to_string(),
                                        product_version: find_match_package_node
                                            .product_version
                                            .to_string(),
                                        ancestors: ancestor_nodes(graph, node_index),
                                    });
                                }
                            }
                        });
                }
            }
        }

        components
    }

    pub async fn query_deps_graph(
        component_name: Option<String>,
        component_purl: Option<Purl>,
        query: Option<Query>,
        distinct_sbom_ids: Vec<String>,
    ) -> Vec<DepSummary> {
        let mut components = Vec::new();
        let graph_manager = GraphMap::get_instance();
        {
            // RwLock for reading hashmap<graph>
            let graph_read_guard = graph_manager.read();
            for distinct_sbom_id in &distinct_sbom_ids {
                if let Some(graph) = graph_read_guard.get(distinct_sbom_id.to_string().as_str()) {
                    if is_cyclic_directed(graph) {
                        log::warn!(
                            "analysis graph of sbom {} has circular references!",
                            distinct_sbom_id
                        );
                    }

                    let mut visited = HashSet::new();

                    // Iterate over matching node indices and process them directly
                    graph
                        .node_indices()
                        .filter(|&i| {
                            if let Some(component_name) = &component_name {
                                graph
                                    .node_weight(i)
                                    .map(|node| node.name.eq(component_name))
                                    .unwrap_or(false)
                            } else if let Some(component_purl) = component_purl.clone() {
                                if let Some(node) = graph.node_weight(i) {
                                    match Purl::from_str(&node.purl).map_err(Error::Purl) {
                                        Ok(purl) => purl == component_purl,
                                        Err(err) => {
                                            log::warn!(
                                                "Error retrieving purl from analysis graph {}",
                                                err
                                            );
                                            false
                                        }
                                    }
                                } else {
                                    false // Return false if the node does not exist
                                }
                            } else if let Some(query) = &query {
                                graph
                                    .node_weight(i)
                                    .map(|node| {
                                        query.apply(&HashMap::from([
                                            ("sbom_id", Value::String(&node.sbom_id)),
                                            ("node_id", Value::String(&node.node_id)),
                                            ("name", Value::String(&node.name)),
                                            ("version", Value::String(&node.version)),
                                        ]))
                                    })
                                    .unwrap_or(false)
                            } else {
                                false
                            }
                        })
                        .for_each(|node_index| {
                            if !visited.contains(&node_index) {
                                visited.insert(node_index);

                                if let Some(find_match_package_node) = graph.node_weight(node_index)
                                {
                                    log::debug!("matched!");
                                    components.push(DepSummary {
                                        sbom_id: find_match_package_node.sbom_id.to_string(),
                                        node_id: find_match_package_node.node_id.to_string(),
                                        purl: find_match_package_node.purl.to_string(),
                                        name: find_match_package_node.name.to_string(),
                                        version: find_match_package_node.version.to_string(),
                                        published: find_match_package_node.published.to_string(),
                                        document_id: find_match_package_node
                                            .document_id
                                            .to_string(),
                                        product_name: find_match_package_node
                                            .product_name
                                            .to_string(),
                                        product_version: find_match_package_node
                                            .product_version
                                            .to_string(),
                                        deps: dep_nodes(graph, node_index, &mut HashSet::new()),
                                    });
                                }
                            }
                        });
                }
            }
        }

        components
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_root_components<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AncestorSummary>, Error> {
        let search_sbom_node_name_subquery = sbom_node::Entity::find()
            .filtering(query.clone())?
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_ancestor_graph(
            None,
            None,
            Option::from(query),
            distinct_sbom_ids,
        )
        .await;

        Ok(paginated.paginate_array(&components))
    }

    pub async fn retrieve_all_sbom_roots_by_name<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        component_name: String,
        connection: &C,
    ) -> Result<Vec<AncNode>, Error> {
        // This function searches for a component(s) by name in a specific sbom, then returns that components
        // root components.

        let distinct_sbom_ids = vec![sbom_id.to_string()];
        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_ancestor_graph(
            Option::from(component_name),
            None,
            None,
            distinct_sbom_ids,
        )
        .await;

        let mut root_components = Vec::new();
        for component in components {
            if let Some(last_ancestor) = component.ancestors.last() {
                if !root_components.contains(last_ancestor) {
                    // we want distinct list
                    root_components.push(last_ancestor.clone());
                }
            }
        }

        Ok(root_components)
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_root_components_by_name<C: ConnectionTrait>(
        &self,
        component_name: String,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AncestorSummary>, Error> {
        let search_sbom_node_exact_name_subquery = sbom_node::Entity::find()
            .filter(sbom_node::Column::Name.eq(component_name.as_str()))
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_exact_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_ancestor_graph(
            Option::from(component_name),
            None,
            None,
            distinct_sbom_ids,
        )
        .await;

        Ok(paginated.paginate_array(&components))
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_root_components_by_purl<C: ConnectionTrait>(
        &self,
        component_purl: Purl,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AncestorSummary>, Error> {
        let search_sbom_node_exact_name_subquery = sbom_node::Entity::find()
            .filter(sbom_node::Column::Name.eq(component_purl.name.as_str()))
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_exact_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_ancestor_graph(
            None,
            Option::from(component_purl),
            None,
            distinct_sbom_ids,
        )
        .await;

        Ok(paginated.paginate_array(&components))
    }

    #[instrument(skip(self, connection), err)]
    pub async fn retrieve_deps<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<DepSummary>, Error> {
        let search_sbom_node_name_subquery = sbom_node::Entity::find()
            .filtering(query.clone())?
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components =
            AnalysisService::query_deps_graph(None, None, Option::from(query), distinct_sbom_ids)
                .await;

        Ok(paginated.paginate_array(&components))
    }

    pub async fn retrieve_deps_by_name<C: ConnectionTrait>(
        &self,
        component_name: String,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<DepSummary>, Error> {
        let search_sbom_node_exact_name_subquery = sbom_node::Entity::find()
            .filter(sbom_node::Column::Name.eq(component_name.as_str()))
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_exact_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_deps_graph(
            Option::from(component_name),
            None,
            None,
            distinct_sbom_ids,
        )
        .await;

        Ok(paginated.paginate_array(&components))
    }

    pub async fn retrieve_deps_by_purl<C: ConnectionTrait>(
        &self,
        component_purl: Purl,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<DepSummary>, Error> {
        let search_sbom_node_exact_name_subquery = sbom_node::Entity::find()
            .filter(sbom_node::Column::Name.eq(component_purl.name.as_str()))
            .select_only()
            .column(sbom_node::Column::SbomId)
            .distinct()
            .into_query();
        let distinct_sbom_ids: Vec<String> = sbom::Entity::find()
            .filter(sbom::Column::SbomId.in_subquery(search_sbom_node_exact_name_subquery))
            .select()
            .order_by(sbom::Column::DocumentId, Order::Asc)
            .order_by(sbom::Column::Published, Order::Desc)
            .all(connection)
            .await?
            .into_iter()
            .map(|record| record.sbom_id.to_string()) // Assuming sbom_id is of type String
            .collect();

        load_graphs(connection, &distinct_sbom_ids).await;

        let components = AnalysisService::query_deps_graph(
            None,
            Option::from(component_purl),
            None,
            distinct_sbom_ids,
        )
        .await;

        Ok(paginated.paginate_array(&components))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use test_context::test_context;
    use test_log::test;
    use trustify_common::model::Paginated;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json", "spdx/simple.json"])
            .await?; //double ingestion intended

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_root_components(Query::q("DD"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .purl,
            "pkg:rpm/redhat/AA@0.0.0?arch=src".to_string()
        );
        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .node_id,
            "SPDXRef-AA".to_string()
        );
        assert_eq!(analysis_graph.total, 1);

        // ensure we set implicit relationship on component with no defined relationships
        let analysis_graph = service
            .retrieve_root_components(Query::q("EE"), Paginated::default(), &ctx.db)
            .await
            .unwrap();
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_analysis_cyclonedx_service(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["cyclonedx/simple.json", "cyclonedx/simple.json"])
            .await?; //double ingestion intended

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_root_components(Query::q("DD"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .purl,
            "pkg:rpm/redhat/AA@0.0.0?arch=src".to_string()
        );
        let node = analysis_graph
            .items
            .last()
            .unwrap()
            .ancestors
            .last()
            .unwrap();
        assert_eq!(node.node_id, "aa".to_string());
        assert_eq!(node.name, "AA".to_string());
        assert_eq!(analysis_graph.total, 1);

        // ensure we set implicit relationship on component with no defined relationships
        let analysis_graph = service
            .retrieve_root_components(Query::q("EE"), Paginated::default(), &ctx.db)
            .await
            .unwrap();
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_by_name_analysis_service(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_root_components_by_name("B".to_string(), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .purl,
            "pkg:rpm/redhat/A@0.0.0?arch=src".to_string()
        );
        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .node_id,
            "SPDXRef-A".to_string()
        );
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_by_purl_analysis_service(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();

        let component_purl: Purl = Purl::from_str("pkg:rpm/redhat/B@0.0.0").map_err(Error::Purl)?;

        let analysis_graph = service
            .retrieve_root_components_by_purl(component_purl, Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .purl,
            "pkg:rpm/redhat/A@0.0.0?arch=src".to_string()
        );
        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .node_id,
            "SPDXRef-A".to_string()
        );
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_quarkus_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_root_components(Query::q("spymemcached"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(analysis_graph.items.last().unwrap().ancestors.last().unwrap().purl,
                   "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?type=pom&repository_url=https://maven.repository.redhat.com/ga/".to_string()
        );
        assert_eq!(
            analysis_graph
                .items
                .last()
                .unwrap()
                .ancestors
                .last()
                .unwrap()
                .node_id,
            "SPDXRef-e24fec28-1001-499c-827f-2e2e5f2671b5".to_string()
        );

        Ok(assert_eq!(analysis_graph.total, 2))
    }

    // TODO: this test passes when run individually.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    #[ignore]
    async fn test_status_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();
        let _load_all_graphs = service.load_all_graphs(&ctx.db).await;
        let analysis_status = service.status(&ctx.db).await.unwrap();

        assert_eq!(analysis_status.sbom_count, 1);
        assert_eq!(analysis_status.graph_count, 1);

        let _clear_all_graphs = service.clear_all_graphs().await;

        ctx.ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

        let analysis_status = service.status(&ctx.db).await.unwrap();

        assert_eq!(analysis_status.sbom_count, 3);
        assert_eq!(analysis_status.graph_count, 0);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps(Query::q("AA"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(analysis_graph.total, 1);

        // ensure we set implicit relationship on component with no defined relationships
        let analysis_graph = service
            .retrieve_root_components(Query::q("EE"), Paginated::default(), &ctx.db)
            .await
            .unwrap();
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_deps_cyclonedx_service(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps(Query::q("AA"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(analysis_graph.total, 1);

        // ensure we set implicit relationship on component with no defined relationships
        let analysis_graph = service
            .retrieve_root_components(Query::q("EE"), Paginated::default(), &ctx.db)
            .await
            .unwrap();
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_by_name_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps_by_name("A".to_string(), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph.items[0].purl,
            "pkg:rpm/redhat/A@0.0.0?arch=src".to_string()
        );
        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_simple_by_purl_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/simple.json"]).await?;

        let service = AnalysisService::new();

        let component_purl: Purl =
            Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src").map_err(Error::Purl)?;

        let analysis_graph = service
            .retrieve_deps_by_purl(component_purl, Paginated::default(), &ctx.db)
            .await
            .unwrap();

        assert_eq!(
            analysis_graph.items[0].purl,
            "pkg:rpm/redhat/AA@0.0.0?arch=src".to_string()
        );

        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_quarkus_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps(Query::q("spymemcached"), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        Ok(assert_eq!(analysis_graph.total, 2))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_circular_deps_cyclonedx_service(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["cyclonedx/cyclonedx-circular.json"])
            .await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps_by_name("junit-bom".to_string(), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_circular_deps_spdx_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/loop.json"]).await?;

        let service = AnalysisService::new();

        let analysis_graph = service
            .retrieve_deps_by_name("A".to_string(), Paginated::default(), &ctx.db)
            .await
            .unwrap();

        Ok(assert_eq!(analysis_graph.total, 1))
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test_retrieve_all_sbom_roots_by_name1(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
            .await?;

        let service = AnalysisService::new();
        let component_name = "quarkus-vertx-http".to_string();

        let analysis_graph = service
            .retrieve_root_components(Query::q(&component_name), Paginated::default(), &ctx.db)
            .await?;

        let sbom_id = analysis_graph
            .items
            .last()
            .unwrap()
            .sbom_id
            .parse::<Uuid>()?;

        let roots = service
            .retrieve_all_sbom_roots_by_name(sbom_id, component_name, &ctx.db)
            .await?;

        assert_eq!(roots.last().unwrap().name, "quarkus-bom");

        Ok(())
    }
}
