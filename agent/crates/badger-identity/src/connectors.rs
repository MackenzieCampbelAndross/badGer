use crate::types::{IdentityObservation, IdentitySource};
use badger_common::BadgerResult;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectorStatus {
    Healthy,
    Degraded { reason: String },
    Unavailable { reason: String },
}

pub trait IdentityConnector: Send + Sync {
    fn name(&self) -> &str;
    fn connector_type(&self) -> IdentitySource;
    fn status(&self) -> ConnectorStatus;
    fn discover(&self, tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>>;
}

// ---------------------------------------------------------------------------
// 1. Linux Process Discovery Connector
// ---------------------------------------------------------------------------
pub struct LinuxProcessConnector {
    proc_root: String,
}

impl Default for LinuxProcessConnector {
    fn default() -> Self {
        Self::new("/proc")
    }
}

impl LinuxProcessConnector {
    pub fn new(proc_root: &str) -> Self {
        Self {
            proc_root: proc_root.to_string(),
        }
    }
}

impl IdentityConnector for LinuxProcessConnector {
    fn name(&self) -> &str {
        "linux_process_connector"
    }

    fn connector_type(&self) -> IdentitySource {
        IdentitySource::LinuxProcFs
    }

    fn status(&self) -> ConnectorStatus {
        let p = Path::new(&self.proc_root);
        if p.exists() && p.is_dir() {
            ConnectorStatus::Healthy
        } else {
            ConnectorStatus::Unavailable {
                reason: format!("Procfs root '{}' not found", self.proc_root),
            }
        }
    }

    fn discover(&self, tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>> {
        let mut observations = Vec::new();
        let proc_path = Path::new(&self.proc_root);

        if !proc_path.exists() {
            return Ok(observations);
        }

        let entries = match fs::read_dir(proc_path) {
            Ok(e) => e,
            Err(_) => return Ok(observations),
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Check if directory name is numeric (PID)
            if let Ok(pid) = name_str.parse::<u32>() {
                let pid_dir = entry.path();
                let status_path = pid_dir.join("status");
                let cmdline_path = pid_dir.join("cmdline");
                let cgroup_path = pid_dir.join("cgroup");

                let mut raw_attrs = HashMap::new();
                raw_attrs.insert("pid".to_string(), pid.to_string());

                // Read /proc/[pid]/status
                if let Ok(status_content) = fs::read_to_string(&status_path) {
                    for line in status_content.lines() {
                        if line.starts_with("Name:") {
                            raw_attrs.insert(
                                "process_name".to_string(),
                                line.trim_start_matches("Name:").trim().to_string(),
                            );
                        } else if line.starts_with("Uid:") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 1 {
                                raw_attrs.insert("real_uid".to_string(), parts[1].to_string());
                            }
                            if parts.len() > 2 {
                                raw_attrs.insert("effective_uid".to_string(), parts[2].to_string());
                            }
                        } else if line.starts_with("Gid:") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 1 {
                                raw_attrs.insert("real_gid".to_string(), parts[1].to_string());
                            }
                        } else if line.starts_with("PPid:") {
                            raw_attrs.insert(
                                "ppid".to_string(),
                                line.trim_start_matches("PPid:").trim().to_string(),
                            );
                        }
                    }
                }

                // Read /proc/[pid]/cmdline
                if let Ok(cmd_bytes) = fs::read(&cmdline_path) {
                    let cmdline = cmd_bytes
                        .split(|&b| b == 0)
                        .filter_map(|s| std::str::from_utf8(s).ok())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !cmdline.is_empty() {
                        raw_attrs.insert("cmdline".to_string(), cmdline);
                    }
                }

                // Read /proc/[pid]/cgroup
                if let Ok(cgroup_content) = fs::read_to_string(&cgroup_path) {
                    let first_line = cgroup_content.lines().next().unwrap_or("").trim();
                    if !first_line.is_empty() {
                        raw_attrs.insert("cgroup".to_string(), first_line.to_string());
                    }
                }

                let is_badger = raw_attrs
                    .get("cgroup")
                    .map(|cg| cg.contains("badger"))
                    .unwrap_or(false);

                observations.push(IdentityObservation {
                    observation_id: format!("obs_proc_{}_{}", pid, Uuid::new_v4().simple()),
                    connector_name: self.name().to_string(),
                    source: IdentitySource::LinuxProcFs,
                    tenant_id: tenant_id.to_string(),
                    timestamp: Utc::now(),
                    entity_id: format!("proc:{}", pid),
                    entity_type: if is_badger { "BadgerProcess" } else { "HostProcess" }.to_string(),
                    raw_attributes: raw_attrs,
                    confidence: if is_badger { 0.99 } else { 0.85 },
                });
            }
        }

        Ok(observations)
    }
}

// ---------------------------------------------------------------------------
// 2. BADGER Workload Sandbox Connector
// ---------------------------------------------------------------------------
pub struct BadgerWorkloadConnector {
    active_workloads: std::sync::Arc<std::sync::RwLock<Vec<crate::types::Workload>>>,
}

impl BadgerWorkloadConnector {
    pub fn new(active_workloads: std::sync::Arc<std::sync::RwLock<Vec<crate::types::Workload>>>) -> Self {
        Self { active_workloads }
    }
}

impl IdentityConnector for BadgerWorkloadConnector {
    fn name(&self) -> &str {
        "badger_workload_connector"
    }

    fn connector_type(&self) -> IdentitySource {
        IdentitySource::BadgerSandbox
    }

    fn status(&self) -> ConnectorStatus {
        ConnectorStatus::Healthy
    }

    fn discover(&self, tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>> {
        let workloads = self.active_workloads.read().unwrap();
        let mut observations = Vec::new();

        for wkl in workloads.iter() {
            if wkl.tenant_id == tenant_id {
                let mut attrs = HashMap::new();
                attrs.insert("name".to_string(), wkl.name.clone());
                attrs.insert("spiffe_id".to_string(), wkl.spiffe_id.clone());
                attrs.insert("principal_id".to_string(), wkl.principal_id.clone());
                attrs.insert("policy_id".to_string(), wkl.policy_id.clone());
                attrs.insert("policy_version".to_string(), wkl.policy_version.to_string());
                if let Some(pid) = wkl.pid {
                    attrs.insert("pid".to_string(), pid.to_string());
                }
                if let Some(ref cg) = wkl.cgroup_path {
                    attrs.insert("cgroup_path".to_string(), cg.clone());
                }

                observations.push(IdentityObservation {
                    observation_id: format!("obs_wkl_{}_{}", wkl.id, Uuid::new_v4().simple()),
                    connector_name: self.name().to_string(),
                    source: IdentitySource::BadgerSandbox,
                    tenant_id: tenant_id.to_string(),
                    timestamp: Utc::now(),
                    entity_id: wkl.id.clone(),
                    entity_type: "Workload".to_string(),
                    raw_attributes: attrs,
                    confidence: 1.0,
                });
            }
        }

        Ok(observations)
    }
}

// ---------------------------------------------------------------------------
// 3. Docker Container Connector (Gracefully handles absence)
// ---------------------------------------------------------------------------
pub struct DockerConnector {
    socket_path: String,
}

impl Default for DockerConnector {
    fn default() -> Self {
        Self::new("/var/run/docker.sock")
    }
}

impl DockerConnector {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }
}

impl IdentityConnector for DockerConnector {
    fn name(&self) -> &str {
        "docker_container_connector"
    }

    fn connector_type(&self) -> IdentitySource {
        IdentitySource::DockerDaemon
    }

    fn status(&self) -> ConnectorStatus {
        let p = Path::new(&self.socket_path);
        if p.exists() {
            ConnectorStatus::Healthy
        } else {
            ConnectorStatus::Unavailable {
                reason: format!("Docker socket '{}' not found or daemon not running", self.socket_path),
            }
        }
    }

    fn discover(&self, _tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>> {
        // If docker daemon is unavailable, do NOT fail - return empty observations gracefully
        if !Path::new(&self.socket_path).exists() {
            return Ok(Vec::new());
        }

        // When socket exists, socket discovery can inspect running containers
        let observations = Vec::new();
        Ok(observations)
    }
}

// ---------------------------------------------------------------------------
// 4. Kubernetes In-Cluster Connector (Gracefully handles absence)
// ---------------------------------------------------------------------------
pub struct KubernetesConnector {
    token_path: String,
}

impl Default for KubernetesConnector {
    fn default() -> Self {
        Self::new("/var/run/secrets/kubernetes.io/serviceaccount/token")
    }
}

impl KubernetesConnector {
    pub fn new(token_path: &str) -> Self {
        Self {
            token_path: token_path.to_string(),
        }
    }
}

impl IdentityConnector for KubernetesConnector {
    fn name(&self) -> &str {
        "kubernetes_cluster_connector"
    }

    fn connector_type(&self) -> IdentitySource {
        IdentitySource::KubernetesApi
    }

    fn status(&self) -> ConnectorStatus {
        let p = Path::new(&self.token_path);
        let has_kubeconfig = std::env::var("KUBECONFIG").is_ok();
        if p.exists() || has_kubeconfig {
            ConnectorStatus::Healthy
        } else {
            ConnectorStatus::Unavailable {
                reason: "Kubernetes in-cluster service account or KUBECONFIG environment variable not present".to_string(),
            }
        }
    }

    fn discover(&self, _tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>> {
        // If not in a Kubernetes cluster, return empty cleanly
        if !Path::new(&self.token_path).exists() && std::env::var("KUBECONFIG").is_err() {
            return Ok(Vec::new());
        }

        let observations = Vec::new();
        Ok(observations)
    }
}

// ---------------------------------------------------------------------------
// Connector Registry
// ---------------------------------------------------------------------------
pub struct ConnectorRegistry {
    connectors: Vec<Box<dyn IdentityConnector>>,
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self {
            connectors: Vec::new(),
        }
    }

    pub fn register(&mut self, connector: Box<dyn IdentityConnector>) {
        self.connectors.push(connector);
    }

    pub fn statuses(&self) -> Vec<(&str, ConnectorStatus)> {
        self.connectors
            .iter()
            .map(|c| (c.name(), c.status()))
            .collect()
    }

    pub fn run_discovery(&self, tenant_id: &str) -> Vec<IdentityObservation> {
        let mut all_obs = Vec::new();
        for c in &self.connectors {
            let status = c.status();
            match status {
                ConnectorStatus::Healthy | ConnectorStatus::Degraded { .. } => {
                    if let Ok(mut obs) = c.discover(tenant_id) {
                        all_obs.append(&mut obs);
                    }
                }
                ConnectorStatus::Unavailable { .. } => {
                    // Gracefully skip unavailable connectors
                }
            }
        }
        all_obs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_procfs_connector_status() {
        let conn = LinuxProcessConnector::new("/proc");
        let status = conn.status();
        // On Linux/WSL2, /proc exists; on Windows host tests it might be Unavailable
        if Path::new("/proc").exists() {
            assert_eq!(status, ConnectorStatus::Healthy);
        } else {
            assert!(matches!(status, ConnectorStatus::Unavailable { .. }));
        }
    }

    #[test]
    fn test_docker_and_k8s_graceful_unavailability() {
        let docker = DockerConnector::new("/nonexistent/docker.sock");
        assert!(matches!(docker.status(), ConnectorStatus::Unavailable { .. }));
        let obs = docker.discover("tenant-1").unwrap();
        assert!(obs.is_empty());

        let k8s = KubernetesConnector::new("/nonexistent/k8s/token");
        assert!(matches!(k8s.status(), ConnectorStatus::Unavailable { .. }));
        let obs_k8s = k8s.discover("tenant-1").unwrap();
        assert!(obs_k8s.is_empty());
    }
}
