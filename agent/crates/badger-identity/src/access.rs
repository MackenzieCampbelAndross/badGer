use crate::graph::{EdgeDirection, IdentityGraph};
use crate::types::{Capability, RelationshipType, Resource};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessProvenance {
    Direct,
    Inherited { from_id: String },
    Delegated { via_chain: Vec<String> },
    CredentialAssociated { credential_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePermission {
    pub entity_id: String,
    pub resource_id: String,
    pub resource_identifier: String,
    pub action: String,
    pub provenance: AccessProvenance,
    pub confidence: u8, // 0 - 100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverPrivilegedFinding {
    pub entity_id: String,
    pub resource_id: String,
    pub granted_actions: Vec<String>,
    pub observed_actions: Vec<String>,
    pub unused_actions: Vec<String>,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default)]
pub struct EffectiveAccessAnalyzer {
    capabilities: HashMap<String, Vec<Capability>>, // resource_id -> Vec<Capability>
    resources: HashMap<String, Resource>,           // resource_id -> Resource
    observed_actions: HashMap<(String, String), HashSet<String>>, // (entity_id, resource_id) -> HashSet<action>
}

impl EffectiveAccessAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_resource(&mut self, resource: Resource) {
        self.resources.insert(resource.id.clone(), resource);
    }

    pub fn register_capability(&mut self, cap: Capability) {
        self.capabilities
            .entry(cap.resource_id.clone())
            .or_default()
            .push(cap);
    }

    pub fn record_observed_action(&mut self, entity_id: &str, resource_id: &str, action: &str) {
        self.observed_actions
            .entry((entity_id.to_string(), resource_id.to_string()))
            .or_default()
            .insert(action.to_string());
    }

    /// Computes the complete effective access permissions for an entity in the graph
    pub fn compute_effective_access(
        &self,
        graph: &IdentityGraph,
        entity_id: &str,
    ) -> Vec<EffectivePermission> {
        let mut permissions = Vec::new();
        let mut visited_entities = HashSet::new();

        self.traverse_effective_access(
            graph,
            entity_id,
            entity_id,
            Vec::new(),
            &mut visited_entities,
            &mut permissions,
        );

        permissions
    }

    fn traverse_effective_access(
        &self,
        graph: &IdentityGraph,
        original_entity: &str,
        current_entity: &str,
        delegation_chain: Vec<String>,
        visited: &mut HashSet<String>,
        results: &mut Vec<EffectivePermission>,
    ) {
        if visited.contains(current_entity) {
            return;
        }
        visited.insert(current_entity.to_string());

        // 1. Direct CAN_ACCESS relationships from current_entity
        let access_edges = graph.get_neighbors(
            current_entity,
            EdgeDirection::Outgoing,
            Some(&[RelationshipType::CAN_ACCESS]),
        );

        for edge in access_edges {
            let resource_id = &edge.target_id;
            let res_ident = self
                .resources
                .get(resource_id)
                .map(|r| r.identifier.clone())
                .unwrap_or_else(|| resource_id.clone());

            let prov = if original_entity == current_entity {
                AccessProvenance::Direct
            } else if !delegation_chain.is_empty() {
                AccessProvenance::Delegated {
                    via_chain: delegation_chain.clone(),
                }
            } else {
                AccessProvenance::Inherited {
                    from_id: current_entity.to_string(),
                }
            };

            // Get capabilities defined for resource
            if let Some(caps) = self.capabilities.get(resource_id) {
                for cap in caps {
                    results.push(EffectivePermission {
                        entity_id: original_entity.to_string(),
                        resource_id: resource_id.clone(),
                        resource_identifier: res_ident.clone(),
                        action: cap.action.clone(),
                        provenance: prov.clone(),
                        confidence: (edge.confidence * 100.0) as u8,
                    });
                }
            } else {
                // If no granular capability defined, treat as general access
                results.push(EffectivePermission {
                    entity_id: original_entity.to_string(),
                    resource_id: resource_id.clone(),
                    resource_identifier: res_ident,
                    action: "access".to_string(),
                    provenance: prov,
                    confidence: (edge.confidence * 100.0) as u8,
                });
            }
        }

        // 2. Credential-associated access: current_entity -> USES_CREDENTIAL -> credential -> CAN_ACCESS -> resource
        let cred_edges = graph.get_neighbors(
            current_entity,
            EdgeDirection::Outgoing,
            Some(&[RelationshipType::USES_CREDENTIAL]),
        );

        for edge in cred_edges {
            let cred_id = &edge.target_id;
            let cred_access = graph.get_neighbors(
                cred_id,
                EdgeDirection::Outgoing,
                Some(&[RelationshipType::CAN_ACCESS]),
            );

            for c_edge in cred_access {
                let resource_id = &c_edge.target_id;
                let res_ident = self
                    .resources
                    .get(resource_id)
                    .map(|r| r.identifier.clone())
                    .unwrap_or_else(|| resource_id.clone());

                results.push(EffectivePermission {
                    entity_id: original_entity.to_string(),
                    resource_id: resource_id.clone(),
                    resource_identifier: res_ident,
                    action: "credential_scope".to_string(),
                    provenance: AccessProvenance::CredentialAssociated {
                        credential_id: cred_id.clone(),
                    },
                    confidence: 90,
                });
            }
        }

        // 3. Delegation: current_entity -> DELEGATES_TO -> next_entity
        let deleg_edges = graph.get_neighbors(
            current_entity,
            EdgeDirection::Outgoing,
            Some(&[RelationshipType::DELEGATES_TO]),
        );

        for edge in deleg_edges {
            let mut next_chain = delegation_chain.clone();
            next_chain.push(edge.target_id.clone());

            self.traverse_effective_access(
                graph,
                original_entity,
                &edge.target_id,
                next_chain,
                visited,
                results,
            );
        }

        // 4. Principal ownership inheritance: principal -> OWNS -> workload (if current is workload, also check owner)
        let owner_edges = graph.get_neighbors(
            current_entity,
            EdgeDirection::Incoming,
            Some(&[RelationshipType::OWNS]),
        );

        for edge in owner_edges {
            self.traverse_effective_access(
                graph,
                original_entity,
                &edge.source_id,
                delegation_chain.clone(),
                visited,
                results,
            );
        }
    }

    /// Identifies over-privileged identities where granted capabilities exceed observed activity
    pub fn detect_over_privileged(&self, permissions: &[EffectivePermission]) -> Vec<OverPrivilegedFinding> {
        let mut grouped: HashMap<(String, String), HashSet<String>> = HashMap::new();

        for p in permissions {
            grouped
                .entry((p.entity_id.clone(), p.resource_id.clone()))
                .or_default()
                .insert(p.action.clone());
        }

        let mut findings = Vec::new();

        for ((entity_id, resource_id), granted_set) in grouped {
            let empty_obs = HashSet::new();
            let observed_set = self
                .observed_actions
                .get(&(entity_id.clone(), resource_id.clone()))
                .unwrap_or(&empty_obs);

            let unused: Vec<String> = granted_set
                .difference(observed_set)
                .cloned()
                .collect();

            // If entity has high privilege like "admin" or "write" but only uses "read" or nothing
            if !unused.is_empty() && (unused.contains(&"admin".to_string()) || unused.contains(&"write".to_string())) {
                findings.push(OverPrivilegedFinding {
                    entity_id: entity_id.clone(),
                    resource_id: resource_id.clone(),
                    granted_actions: granted_set.into_iter().collect(),
                    observed_actions: observed_set.iter().cloned().collect(),
                    unused_actions: unused.clone(),
                    severity: if unused.contains(&"admin".to_string()) {
                        "High".to_string()
                    } else {
                        "Medium".to_string()
                    },
                    recommendation: format!(
                        "Revoke unused actions [{}] from entity '{}' on resource '{}'",
                        unused.join(", "),
                        entity_id,
                        resource_id
                    ),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Relationship, RelationshipKind, ResourceType};
    use chrono::Utc;

    #[test]
    fn test_effective_access_transitive_and_delegation() {
        let mut graph = IdentityGraph::new();
        let mut analyzer = EffectiveAccessAnalyzer::new();

        analyzer.register_resource(Resource {
            id: "res-db-prod".to_string(),
            tenant_id: "tenant-1".to_string(),
            resource_type: ResourceType::Database,
            identifier: "postgres://db.prod/users".to_string(),
            labels: HashMap::new(),
            attributes: HashMap::new(),
        });

        analyzer.register_capability(Capability {
            id: "cap-read".to_string(),
            action: "read".to_string(),
            resource_id: "res-db-prod".to_string(),
            conditions: HashMap::new(),
        });

        analyzer.register_capability(Capability {
            id: "cap-write".to_string(),
            action: "write".to_string(),
            resource_id: "res-db-prod".to_string(),
            conditions: HashMap::new(),
        });

        // Agent-1 DELEGATES_TO Agent-2
        graph.add_relationship(Relationship {
            id: "rel-deleg".to_string(),
            tenant_id: "tenant-1".to_string(),
            source_id: "agent-1".to_string(),
            target_id: "agent-2".to_string(),
            relationship_type: RelationshipType::DELEGATES_TO,
            kind: RelationshipKind::Direct,
            confidence: 1.0,
            source_attribution: "test".to_string(),
            valid_from: Utc::now(),
            valid_to: None,
            metadata: HashMap::new(),
        });

        // Agent-2 CAN_ACCESS res-db-prod
        graph.add_relationship(Relationship {
            id: "rel-acc".to_string(),
            tenant_id: "tenant-1".to_string(),
            source_id: "agent-2".to_string(),
            target_id: "res-db-prod".to_string(),
            relationship_type: RelationshipType::CAN_ACCESS,
            kind: RelationshipKind::Direct,
            confidence: 0.95,
            source_attribution: "test".to_string(),
            valid_from: Utc::now(),
            valid_to: None,
            metadata: HashMap::new(),
        });

        // Compute effective access for agent-1 (should transitively get access via delegation)
        let perms = analyzer.compute_effective_access(&graph, "agent-1");
        assert_eq!(perms.len(), 2);
        assert!(perms.iter().any(|p| p.action == "read"));
        assert!(perms.iter().any(|p| p.action == "write"));

        // Test over-privileged detection
        analyzer.record_observed_action("agent-1", "res-db-prod", "read");
        let over_priv = analyzer.detect_over_privileged(&perms);
        assert_eq!(over_priv.len(), 1);
        assert_eq!(over_priv[0].unused_actions, vec!["write"]);
    }
}
