use crate::types::{Relationship, RelationshipType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityNode {
    pub id: String,
    pub tenant_id: String,
    pub entity_type: String, // "Tenant", "Principal", "Workload", "Credential", "Resource"
    pub label: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeDirection {
    Outgoing,
    Incoming,
    Both,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityGraph {
    nodes: HashMap<String, IdentityNode>,
    outgoing: HashMap<String, Vec<Relationship>>,
    incoming: HashMap<String, Vec<Relationship>>,
}

impl IdentityGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: IdentityNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn get_node(&self, id: &str) -> Option<&IdentityNode> {
        self.nodes.get(id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.outgoing.values().map(|v| v.len()).sum()
    }

    pub fn add_relationship(&mut self, rel: Relationship) {
        // Ensure source and target node placeholders exist if not present
        if !self.nodes.contains_key(&rel.source_id) {
            self.nodes.insert(
                rel.source_id.clone(),
                IdentityNode {
                    id: rel.source_id.clone(),
                    tenant_id: rel.tenant_id.clone(),
                    entity_type: "Unknown".to_string(),
                    label: rel.source_id.clone(),
                    properties: HashMap::new(),
                },
            );
        }
        if !self.nodes.contains_key(&rel.target_id) {
            self.nodes.insert(
                rel.target_id.clone(),
                IdentityNode {
                    id: rel.target_id.clone(),
                    tenant_id: rel.tenant_id.clone(),
                    entity_type: "Unknown".to_string(),
                    label: rel.target_id.clone(),
                    properties: HashMap::new(),
                },
            );
        }

        self.outgoing
            .entry(rel.source_id.clone())
            .or_default()
            .push(rel.clone());
        self.incoming
            .entry(rel.target_id.clone())
            .or_default()
            .push(rel);
    }

    pub fn get_neighbors(
        &self,
        node_id: &str,
        direction: EdgeDirection,
        rel_type_filter: Option<&[RelationshipType]>,
    ) -> Vec<Relationship> {
        let mut results = Vec::new();

        let matches_filter = |rel: &Relationship| -> bool {
            if let Some(types) = rel_type_filter {
                types.contains(&rel.relationship_type)
            } else {
                true
            }
        };

        if direction == EdgeDirection::Outgoing || direction == EdgeDirection::Both {
            if let Some(edges) = self.outgoing.get(node_id) {
                for edge in edges {
                    if matches_filter(edge) {
                        results.push(edge.clone());
                    }
                }
            }
        }

        if direction == EdgeDirection::Incoming || direction == EdgeDirection::Both {
            if let Some(edges) = self.incoming.get(node_id) {
                for edge in edges {
                    if matches_filter(edge) {
                        results.push(edge.clone());
                    }
                }
            }
        }

        results
    }

    /// Finds all paths from `from_node` to `to_node` up to `max_depth` edges.
    pub fn find_paths(&self, from_node: &str, to_node: &str, max_depth: usize) -> Vec<Vec<Relationship>> {
        let mut all_paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();

        self.dfs_paths(
            from_node,
            to_node,
            max_depth,
            &mut current_path,
            &mut visited,
            &mut all_paths,
        );

        all_paths
    }

    fn dfs_paths(
        &self,
        current: &str,
        target: &str,
        max_depth: usize,
        current_path: &mut Vec<Relationship>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<Vec<Relationship>>,
    ) {
        if current == target && !current_path.is_empty() {
            all_paths.push(current_path.clone());
            return;
        }

        if current_path.len() >= max_depth {
            return;
        }

        visited.insert(current.to_string());

        if let Some(edges) = self.outgoing.get(current) {
            for edge in edges {
                if !visited.contains(&edge.target_id) {
                    current_path.push(edge.clone());
                    self.dfs_paths(
                        &edge.target_id,
                        target,
                        max_depth,
                        current_path,
                        visited,
                        all_paths,
                    );
                    current_path.pop();
                }
            }
        }

        visited.remove(current);
    }

    /// Detects cycles in the directed graph (e.g. delegation cycles).
    pub fn detect_cycles(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut current_path = Vec::new();

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                self.dfs_cycle(
                    node_id,
                    &mut visited,
                    &mut rec_stack,
                    &mut current_path,
                    &mut cycles,
                );
            }
        }

        cycles
    }

    fn dfs_cycle(
        &self,
        current: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        current_path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(current.to_string());
        rec_stack.insert(current.to_string());
        current_path.push(current.to_string());

        if let Some(edges) = self.outgoing.get(current) {
            for edge in edges {
                let neighbor = &edge.target_id;
                if !visited.contains(neighbor) {
                    self.dfs_cycle(neighbor, visited, rec_stack, current_path, cycles);
                } else if rec_stack.contains(neighbor) {
                    // Cycle detected: extract the cycle slice
                    if let Some(pos) = current_path.iter().position(|x| x == neighbor) {
                        let cycle: Vec<String> = current_path[pos..].to_vec();
                        cycles.push(cycle);
                    }
                }
            }
        }

        rec_stack.remove(current);
        current_path.pop();
    }

    /// Filters graph to only elements belonging to `tenant_id`.
    pub fn filter_by_tenant(&self, tenant_id: &str) -> IdentityGraph {
        let mut filtered = IdentityGraph::new();

        for (_id, node) in &self.nodes {
            if node.tenant_id == tenant_id {
                filtered.add_node(node.clone());
            }
        }

        for edges in self.outgoing.values() {
            for edge in edges {
                if edge.tenant_id == tenant_id {
                    filtered.add_relationship(edge.clone());
                }
            }
        }

        filtered
    }

    /// Exports nodes and links formatted for interactive visualization.
    pub fn to_visualization_json(&self) -> serde_json::Value {
        let nodes: Vec<&IdentityNode> = self.nodes.values().collect();
        let mut edges: Vec<&Relationship> = Vec::new();
        for list in self.outgoing.values() {
            for edge in list {
                edges.push(edge);
            }
        }

        serde_json::json!({
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": self.nodes.len(),
                "edge_count": edges.len()
            }
        })
    }

    pub fn nodes(&self) -> &HashMap<String, IdentityNode> {
        &self.nodes
    }

    pub fn outgoing_edges(&self) -> &HashMap<String, Vec<Relationship>> {
        &self.outgoing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RelationshipKind, RelationshipType};
    use chrono::Utc;

    #[test]
    fn test_graph_construction_and_paths() {
        let mut graph = IdentityGraph::new();
        graph.add_node(IdentityNode {
            id: "principal-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            entity_type: "Principal".to_string(),
            label: "Agent-Principal".to_string(),
            properties: HashMap::new(),
        });
        graph.add_node(IdentityNode {
            id: "workload-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            entity_type: "Workload".to_string(),
            label: "Worker-1".to_string(),
            properties: HashMap::new(),
        });
        graph.add_node(IdentityNode {
            id: "cred-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            entity_type: "Credential".to_string(),
            label: "OpenAI-Token".to_string(),
            properties: HashMap::new(),
        });

        graph.add_relationship(Relationship {
            id: "rel-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            source_id: "principal-1".to_string(),
            target_id: "workload-1".to_string(),
            relationship_type: RelationshipType::OWNS,
            kind: RelationshipKind::Direct,
            confidence: 1.0,
            source_attribution: "control-plane".to_string(),
            valid_from: Utc::now(),
            valid_to: None,
            metadata: HashMap::new(),
        });

        graph.add_relationship(Relationship {
            id: "rel-2".to_string(),
            tenant_id: "tenant-a".to_string(),
            source_id: "workload-1".to_string(),
            target_id: "cred-1".to_string(),
            relationship_type: RelationshipType::USES_CREDENTIAL,
            kind: RelationshipKind::Direct,
            confidence: 0.95,
            source_attribution: "ebpf-sensor".to_string(),
            valid_from: Utc::now(),
            valid_to: None,
            metadata: HashMap::new(),
        });

        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);

        let paths = graph.find_paths("principal-1", "cred-1", 5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 2);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = IdentityGraph::new();
        // A -> B -> C -> A (cycle)
        for (src, dst) in [("nodeA", "nodeB"), ("nodeB", "nodeC"), ("nodeC", "nodeA")] {
            graph.add_relationship(Relationship {
                id: format!("{}-{}", src, dst),
                tenant_id: "tenant-a".to_string(),
                source_id: src.to_string(),
                target_id: dst.to_string(),
                relationship_type: RelationshipType::DELEGATES_TO,
                kind: RelationshipKind::Direct,
                confidence: 1.0,
                source_attribution: "test".to_string(),
                valid_from: Utc::now(),
                valid_to: None,
                metadata: HashMap::new(),
            });
        }

        let cycles = graph.detect_cycles();
        assert!(!cycles.is_empty(), "Should detect the cycle A -> B -> C -> A");
    }
}
