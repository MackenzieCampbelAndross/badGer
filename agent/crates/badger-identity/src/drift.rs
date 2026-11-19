use crate::credentials::CredentialIntelligenceStore;
use crate::graph::IdentityGraph;
use crate::types::{
    FindingSeverity, IdentityFinding, IdentityFindingType, RelationshipType, Workload,
};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

pub struct IdentityDriftDetector {
    max_delegation_depth: usize,
}

impl Default for IdentityDriftDetector {
    fn default() -> Self {
        Self {
            max_delegation_depth: 2,
        }
    }
}

impl IdentityDriftDetector {
    pub fn new(max_delegation_depth: usize) -> Self {
        Self {
            max_delegation_depth,
        }
    }

    /// Evaluates the complete identity graph, credential inventory, and active workloads for drift
    pub fn evaluate(
        &self,
        tenant_id: &str,
        graph: &IdentityGraph,
        workloads: &[Workload],
        cred_store: &CredentialIntelligenceStore,
    ) -> Vec<IdentityFinding> {
        let mut findings = Vec::new();

        // 1. Check for unowned workloads (active workloads with no principal or tenant mismatch)
        for w in workloads {
            if w.tenant_id != tenant_id {
                continue;
            }

            if w.principal_id.is_empty() {
                let mut ev = HashMap::new();
                ev.insert("workload_id".to_string(), w.id.clone());
                ev.insert("workload_name".to_string(), w.name.clone());

                findings.push(IdentityFinding {
                    id: format!("fnd_{}", Uuid::new_v4().simple()),
                    tenant_id: tenant_id.to_string(),
                    finding_type: IdentityFindingType::UnownedWorkload,
                    severity: FindingSeverity::High,
                    title: format!("Unowned Workload: {}", w.name),
                    description: format!(
                        "Workload '{}' (ID: {}) is running without an assigned principal identity",
                        w.name, w.id
                    ),
                    entity_id: w.id.clone(),
                    evidence: ev,
                    remediation: "Assign a valid registered principal to the workload or terminate it".to_string(),
                    detected_at: Utc::now(),
                    status: "Open".to_string(),
                });
            }
        }

        // 2. Check for duplicate SPIFFE IDs across active workloads
        let mut spiffe_map: HashMap<String, Vec<&Workload>> = HashMap::new();
        for w in workloads {
            if w.tenant_id == tenant_id && !w.spiffe_id.is_empty() {
                spiffe_map.entry(w.spiffe_id.clone()).or_default().push(w);
            }
        }
        for (spiffe_id, w_list) in spiffe_map {
            if w_list.len() > 1 {
                let wkl_ids: Vec<String> = w_list.iter().map(|w| w.id.clone()).collect();
                let mut ev = HashMap::new();
                ev.insert("spiffe_id".to_string(), spiffe_id.clone());
                ev.insert("workloads".to_string(), wkl_ids.join(", "));

                findings.push(IdentityFinding {
                    id: format!("fnd_{}", Uuid::new_v4().simple()),
                    tenant_id: tenant_id.to_string(),
                    finding_type: IdentityFindingType::DuplicateIdentity,
                    severity: FindingSeverity::Critical,
                    title: format!("Duplicate SPIFFE Identity Detected: {}", spiffe_id),
                    description: format!(
                        "Multiple workloads [{}] claim the identical SPIFFE ID '{}'",
                        wkl_ids.join(", "),
                        spiffe_id
                    ),
                    entity_id: spiffe_id.clone(),
                    evidence: ev,
                    remediation: "Revoke and reissue distinct SPIFFE SVIDs for each workload instance".to_string(),
                    detected_at: Utc::now(),
                    status: "Open".to_string(),
                });
            }
        }

        // 3. Check for credential sharing without explicit delegation
        let credentials = cred_store.list_credentials(tenant_id);
        for cred in &credentials {
            let sharing_workloads = cred_store.get_workloads_sharing_credential(&cred.fingerprint_hmac_sha256);
            if sharing_workloads.len() > 1 {
                // Check if there is an explicit DELEGATES_TO edge between the sharing workloads in graph
                let mut unapproved_sharing = false;
                for i in 0..sharing_workloads.len() {
                    for j in (i + 1)..sharing_workloads.len() {
                        let w1 = &sharing_workloads[i];
                        let w2 = &sharing_workloads[j];
                        let paths_1_to_2 = graph.find_paths(w1, w2, self.max_delegation_depth);
                        let paths_2_to_1 = graph.find_paths(w2, w1, self.max_delegation_depth);

                        let has_delegation = paths_1_to_2.iter().chain(paths_2_to_1.iter()).any(|p| {
                            p.iter().any(|rel| rel.relationship_type == RelationshipType::DELEGATES_TO)
                        });

                        if !has_delegation {
                            unapproved_sharing = true;
                            break;
                        }
                    }
                    if unapproved_sharing {
                        break;
                    }
                }

                if unapproved_sharing {
                    let mut ev = HashMap::new();
                    ev.insert("credential_id".to_string(), cred.id.clone());
                    ev.insert("fingerprint".to_string(), cred.fingerprint_hmac_sha256.clone());
                    ev.insert("workloads".to_string(), sharing_workloads.join(", "));

                    findings.push(IdentityFinding {
                        id: format!("fnd_{}", Uuid::new_v4().simple()),
                        tenant_id: tenant_id.to_string(),
                        finding_type: IdentityFindingType::CredentialSharing,
                        severity: FindingSeverity::High,
                        title: format!("Unapproved Credential Sharing: {}", cred.issuer),
                        description: format!(
                            "Credential '{}' ({}) is shared across workloads [{}] without declared delegation",
                            cred.id, cred.issuer, sharing_workloads.join(", ")
                        ),
                        entity_id: cred.id.clone(),
                        evidence: ev,
                        remediation: "Issue workload-specific scoped credentials or declare explicit delegation in security policy".to_string(),
                        detected_at: Utc::now(),
                        status: "Open".to_string(),
                    });
                }
            }

            // 4. Check for expired credentials still active
            let now = Utc::now();
            if now > cred.expires_at && !cred.is_revoked {
                let mut ev = HashMap::new();
                ev.insert("credential_id".to_string(), cred.id.clone());
                ev.insert("expires_at".to_string(), cred.expires_at.to_rfc3339());
                ev.insert("use_count".to_string(), cred.use_count.to_string());

                findings.push(IdentityFinding {
                    id: format!("fnd_{}", Uuid::new_v4().simple()),
                    tenant_id: tenant_id.to_string(),
                    finding_type: IdentityFindingType::ExpiredCredentialInUse,
                    severity: FindingSeverity::Medium,
                    title: format!("Expired Credential Unrevoked: {}", cred.id),
                    description: format!(
                        "Credential '{}' expired on {} but remains in active credential inventory",
                        cred.id, cred.expires_at
                    ),
                    entity_id: cred.id.clone(),
                    evidence: ev,
                    remediation: "Revoke expired credential and rotate workload to fresh credentials".to_string(),
                    detected_at: Utc::now(),
                    status: "Open".to_string(),
                });
            }
        }

        // 5. Check for Cross-Tenant relationships
        for edges in graph.outgoing_edges().values() {
            for edge in edges {
                if let (Some(src_node), Some(dst_node)) = (graph.get_node(&edge.source_id), graph.get_node(&edge.target_id)) {
                    if src_node.tenant_id != dst_node.tenant_id && (edge.relationship_type == RelationshipType::CAN_ACCESS || edge.relationship_type == RelationshipType::DELEGATES_TO) {
                        let mut ev = HashMap::new();
                        ev.insert("source_entity".to_string(), edge.source_id.clone());
                        ev.insert("source_tenant".to_string(), src_node.tenant_id.clone());
                        ev.insert("target_entity".to_string(), edge.target_id.clone());
                        ev.insert("target_tenant".to_string(), dst_node.tenant_id.clone());

                        findings.push(IdentityFinding {
                            id: format!("fnd_{}", Uuid::new_v4().simple()),
                            tenant_id: tenant_id.to_string(),
                            finding_type: IdentityFindingType::CrossTenantAccessAttempt,
                            severity: FindingSeverity::Critical,
                            title: "Cross-Tenant Access Boundary Violation".to_string(),
                            description: format!(
                                "Entity '{}' (tenant '{}') has relationship '{:?}' to '{}' (tenant '{}')",
                                edge.source_id, src_node.tenant_id, edge.relationship_type, edge.target_id, dst_node.tenant_id
                            ),
                            entity_id: edge.id.clone(),
                            evidence: ev,
                            remediation: "Enforce strict tenant isolation: remove cross-tenant relationship edge immediately".to_string(),
                            detected_at: Utc::now(),
                            status: "Open".to_string(),
                        });
                    }
                }
            }
        }

        // 6. Check for excessive delegation chain depth
        let nodes = graph.nodes();
        for src_id in nodes.keys() {
            for dst_id in nodes.keys() {
                if src_id != dst_id {
                    let paths = graph.find_paths(src_id, dst_id, self.max_delegation_depth + 2);
                    for path in paths {
                        let deleg_count = path.iter().filter(|r| r.relationship_type == RelationshipType::DELEGATES_TO).count();
                        if deleg_count > self.max_delegation_depth {
                            let mut ev = HashMap::new();
                            ev.insert("chain_start".to_string(), src_id.clone());
                            ev.insert("chain_end".to_string(), dst_id.clone());
                            ev.insert("chain_length".to_string(), deleg_count.to_string());

                            findings.push(IdentityFinding {
                                id: format!("fnd_{}", Uuid::new_v4().simple()),
                                tenant_id: tenant_id.to_string(),
                                finding_type: IdentityFindingType::UnexpectedDelegation,
                                severity: FindingSeverity::High,
                                title: "Excessive Delegation Chain Depth".to_string(),
                                description: format!(
                                    "Delegation chain from '{}' to '{}' has {} hops, exceeding limit of {}",
                                    src_id, dst_id, deleg_count, self.max_delegation_depth
                                ),
                                entity_id: src_id.clone(),
                                evidence: ev,
                                remediation: "Shorten delegation chain to prevent confused deputy privilege escalation".to_string(),
                                detected_at: Utc::now(),
                                status: "Open".to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialIntelligenceStore;
    use crate::graph::{IdentityGraph, IdentityNode};
    use crate::types::{CredentialType, Relationship, RelationshipKind, SensorHealthStatus, WorkloadState};
    use chrono::{Duration, Utc};

    #[test]
    fn test_drift_detector_flags_anomalies() {
        let detector = IdentityDriftDetector::new(2);
        let mut graph = IdentityGraph::new();
        let cred_store = CredentialIntelligenceStore::new();

        // Register two workloads
        let wkl1 = Workload {
            id: "wkl-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            principal_id: "".to_string(), // Unowned!
            name: "rogue-agent".to_string(),
            state: WorkloadState::Active,
            spiffe_id: "spiffe://badger.local/ns/tenant-a/sa/rogue/workload/wkl-1".to_string(),
            cgroup_path: None,
            pid: Some(101),
            policy_id: "pol-1".to_string(),
            policy_version: 1,
            metadata: HashMap::new(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            sensor_status: SensorHealthStatus::Protected,
        };

        let wkl2 = Workload {
            id: "wkl-2".to_string(),
            tenant_id: "tenant-a".to_string(),
            principal_id: "prn-2".to_string(),
            name: "normal-agent".to_string(),
            state: WorkloadState::Active,
            spiffe_id: "spiffe://badger.local/ns/tenant-a/sa/rogue/workload/wkl-1".to_string(), // Duplicate SPIFFE!
            cgroup_path: None,
            pid: Some(102),
            policy_id: "pol-1".to_string(),
            policy_version: 1,
            metadata: HashMap::new(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            sensor_status: SensorHealthStatus::Protected,
        };

        // Credential sharing without delegation
        let raw_token = b"shared-secret-token";
        let _c1 = cred_store
            .register_credential(
                "tenant-a",
                "wkl-1",
                "prn-1",
                CredentialType::ApiKey,
                "anthropic",
                "api.anthropic.com",
                vec!["messages".to_string()],
                Utc::now() + Duration::hours(5),
                raw_token,
            )
            .unwrap();

        let _c2 = cred_store
            .register_credential(
                "tenant-a",
                "wkl-2",
                "prn-2",
                CredentialType::ApiKey,
                "anthropic",
                "api.anthropic.com",
                vec!["messages".to_string()],
                Utc::now() + Duration::hours(5),
                raw_token,
            )
            .unwrap();

        // Add cross-tenant edge
        graph.add_node(IdentityNode {
            id: "wkl-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            entity_type: "Workload".to_string(),
            label: "Workload 1".to_string(),
            properties: HashMap::new(),
        });
        graph.add_node(IdentityNode {
            id: "res-victim-tenant".to_string(),
            tenant_id: "tenant-b".to_string(), // Different tenant!
            entity_type: "Resource".to_string(),
            label: "Secret DB".to_string(),
            properties: HashMap::new(),
        });
        graph.add_relationship(Relationship {
            id: "rel-cross".to_string(),
            tenant_id: "tenant-a".to_string(),
            source_id: "wkl-1".to_string(),
            target_id: "res-victim-tenant".to_string(),
            relationship_type: RelationshipType::CAN_ACCESS,
            kind: RelationshipKind::Direct,
            confidence: 1.0,
            source_attribution: "test".to_string(),
            valid_from: Utc::now(),
            valid_to: None,
            metadata: HashMap::new(),
        });

        let findings = detector.evaluate("tenant-a", &graph, &[wkl1, wkl2], &cred_store);

        assert!(
            findings.iter().any(|f| f.finding_type == IdentityFindingType::UnownedWorkload),
            "Must flag unowned workload"
        );
        assert!(
            findings.iter().any(|f| f.finding_type == IdentityFindingType::DuplicateIdentity),
            "Must flag duplicate SPIFFE ID"
        );
        assert!(
            findings.iter().any(|f| f.finding_type == IdentityFindingType::CredentialSharing),
            "Must flag unapproved credential sharing"
        );
        assert!(
            findings.iter().any(|f| f.finding_type == IdentityFindingType::CrossTenantAccessAttempt),
            "Must flag cross-tenant access attempt"
        );
    }
}
