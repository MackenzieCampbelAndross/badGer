use crate::capability::Capability;
use crate::model::Policy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendationType {
    RemoveUnusedFilesystemAccess,
    RestrictNetworkDestinations,
    ReduceProcessPrivileges,
    ShortenCredentialValidity,
    RemoveUnusedDelegation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeastPrivilegeRecommendation {
    pub id: String,
    pub tenant_id: String,
    pub workload_id: String,
    pub recommendation_type: RecommendationType,
    pub severity: String,
    pub current_permission: String,
    pub recommended_restriction: String,
    pub evidence: Vec<String>,
    pub observation_window_seconds: u64,
    pub rationale: String,
}

pub struct LeastPrivilegeEngine {
    observed_fs_reads: HashMap<String, HashSet<String>>, // workload_id -> Set<path>
    observed_net_connects: HashMap<String, HashSet<String>>, // workload_id -> Set<destination:port>
    observed_execs: HashMap<String, HashSet<String>>,    // workload_id -> Set<binary>
}

impl Default for LeastPrivilegeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LeastPrivilegeEngine {
    pub fn new() -> Self {
        Self {
            observed_fs_reads: HashMap::new(),
            observed_net_connects: HashMap::new(),
            observed_execs: HashMap::new(),
        }
    }

    pub fn record_filesystem_access(&mut self, workload_id: &str, path: &str) {
        self.observed_fs_reads
            .entry(workload_id.to_string())
            .or_default()
            .insert(path.to_string());
    }

    pub fn record_network_connection(&mut self, workload_id: &str, destination: &str, port: u16) {
        self.observed_net_connects
            .entry(workload_id.to_string())
            .or_default()
            .insert(format!("{}:{}", destination, port));
    }

    pub fn record_process_execution(&mut self, workload_id: &str, binary: &str) {
        self.observed_execs
            .entry(workload_id.to_string())
            .or_default()
            .insert(binary.to_string());
    }

    /// Evaluates granted policy capabilities against observed telemetry over the window.
    /// Produces actionable, evidence-based recommendations.
    pub fn analyze_policy(
        &self,
        workload_id: &str,
        policy: &Policy,
        window_seconds: u64,
    ) -> Vec<LeastPrivilegeRecommendation> {
        let mut recommendations = Vec::new();

        // 1. Analyze network capabilities
        let empty_net = HashSet::new();
        let observed_net = self.observed_net_connects.get(workload_id).unwrap_or(&empty_net);

        for cap in &policy.allowed_capabilities {
            if let Capability::NetConnect { destination, min_port, max_port, .. } = cap {
                if destination == "*" || destination == "0.0.0.0/0" {
                    // Broad wildcard granted
                    let observed_list: Vec<String> = observed_net.iter().cloned().collect();
                    let rec = if observed_list.is_empty() {
                        "Revoke network connection capability entirely (zero egress connections observed)".to_string()
                    } else {
                        format!("Restrict destination from wildcard '*' to observed endpoints: [{}]", observed_list.join(", "))
                    };

                    recommendations.push(LeastPrivilegeRecommendation {
                        id: format!("rec_{}", Uuid::new_v4().simple()),
                        tenant_id: policy.tenant_id.clone(),
                        workload_id: workload_id.to_string(),
                        recommendation_type: RecommendationType::RestrictNetworkDestinations,
                        severity: "High".to_string(),
                        current_permission: format!("NetConnect({}: {}-{})", destination, min_port, max_port),
                        recommended_restriction: rec,
                        evidence: observed_list.iter().map(|e| format!("Observed egress connection to {}", e)).collect(),
                        observation_window_seconds: window_seconds,
                        rationale: "Workload has unrestricted wildcard network egress permission but only communicates with a finite set of destinations".to_string(),
                    });
                }
            }
        }

        // 2. Analyze filesystem capabilities
        let empty_fs = HashSet::new();
        let observed_fs = self.observed_fs_reads.get(workload_id).unwrap_or(&empty_fs);

        for cap in &policy.allowed_capabilities {
            if let Capability::FsRead { path, recursive } = cap {
                if *recursive && (path == "/" || path == "/workspace") {
                    let observed_files: Vec<String> = observed_fs.iter().cloned().collect();
                    if !observed_files.is_empty() && observed_files.len() <= 5 {
                        recommendations.push(LeastPrivilegeRecommendation {
                            id: format!("rec_{}", Uuid::new_v4().simple()),
                            tenant_id: policy.tenant_id.clone(),
                            workload_id: workload_id.to_string(),
                            recommendation_type: RecommendationType::RemoveUnusedFilesystemAccess,
                            severity: "Medium".to_string(),
                            current_permission: format!("FsRead(path: {}, recursive: true)", path),
                            recommended_restriction: format!("Constrain FsRead paths specifically to: [{}]", observed_files.join(", ")),
                            evidence: observed_files.iter().map(|f| format!("Read access to {}", f)).collect(),
                            observation_window_seconds: window_seconds,
                            rationale: "Broad recursive directory access granted, but workload only accessed specific files".to_string(),
                        });
                    }
                }
            }
        }

        recommendations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_least_privilege_generates_evidence_backed_recommendation() {
        let mut engine = LeastPrivilegeEngine::new();
        engine.record_network_connection("wkl-agent", "api.anthropic.com", 443);

        let cap = Capability::NetConnect {
            destination: "*".to_string(),
            min_port: 0,
            max_port: 65535,
            protocol: "any".to_string(),
        };

        let pol = Policy {
            id: "pol-broad".to_string(),
            tenant_id: "tenant-corp".to_string(),
            name: "Broad Policy".to_string(),
            version: 1,
            priority: 1,
            principal_selectors: vec!["*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: vec![cap],
            denied_capabilities: Vec::new(),
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };

        let recs = engine.analyze_policy("wkl-agent", &pol, 3600);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].recommendation_type, RecommendationType::RestrictNetworkDestinations);
        assert!(recs[0].recommended_restriction.contains("api.anthropic.com:443"));
        assert!(!recs[0].evidence.is_empty());
    }
}
