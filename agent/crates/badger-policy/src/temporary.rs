use crate::capability::Capability;
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Dynamic, time-bounded capability grant issued for a specific ephemeral task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporaryCapabilityGrant {
    pub grant_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub workload_id: String,
    pub capability: Capability,
    pub reason: String,
    pub granted_at_unix: i64,
    pub expires_at_unix: i64,
    pub approved_by: Option<String>,
    pub is_revoked: bool,
    pub revoked_at_unix: Option<i64>,
}

impl TemporaryCapabilityGrant {
    /// Returns true if the grant is active (not expired and not revoked) at `now_unix`
    pub fn is_active(&self, now_unix: i64) -> bool {
        !self.is_revoked && now_unix >= self.granted_at_unix && now_unix <= self.expires_at_unix
    }
}

pub struct TemporaryCapabilityStore {
    grants: Arc<RwLock<HashMap<String, TemporaryCapabilityGrant>>>,
    workload_index: Arc<RwLock<HashMap<String, Vec<String>>>>, // workload_id -> Vec<grant_id>
}

impl Default for TemporaryCapabilityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TemporaryCapabilityStore {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(RwLock::new(HashMap::new())),
            workload_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Grants a temporary, time-bounded capability
    pub fn grant_temporary_capability(
        &self,
        tenant_id: &str,
        principal_id: &str,
        workload_id: &str,
        capability: Capability,
        duration_seconds: i64,
        reason: &str,
        approved_by: Option<&str>,
    ) -> BadgerResult<TemporaryCapabilityGrant> {
        if duration_seconds <= 0 {
            return Err(BadgerError::PolicyInvalid(
                "Duration for temporary capability grant must be > 0 seconds".to_string(),
            ));
        }

        let now = Utc::now().timestamp();
        let grant_id = format!("tgr_{}", Uuid::new_v4().simple());

        let grant = TemporaryCapabilityGrant {
            grant_id: grant_id.clone(),
            tenant_id: tenant_id.to_string(),
            principal_id: principal_id.to_string(),
            workload_id: workload_id.to_string(),
            capability,
            reason: reason.to_string(),
            granted_at_unix: now,
            expires_at_unix: now + duration_seconds,
            approved_by: approved_by.map(|s| s.to_string()),
            is_revoked: false,
            revoked_at_unix: None,
        };

        let mut g_map = self.grants.write().unwrap();
        g_map.insert(grant_id.clone(), grant.clone());

        let mut w_idx = self.workload_index.write().unwrap();
        w_idx
            .entry(workload_id.to_string())
            .or_default()
            .push(grant_id);

        Ok(grant)
    }

    /// Revokes an active temporary grant before its scheduled expiration
    pub fn revoke_grant(&self, grant_id: &str) -> BadgerResult<()> {
        let mut g_map = self.grants.write().unwrap();
        if let Some(grant) = g_map.get_mut(grant_id) {
            grant.is_revoked = true;
            grant.revoked_at_unix = Some(Utc::now().timestamp());
            Ok(())
        } else {
            Err(BadgerError::PolicyInvalid(format!(
                "Temporary capability grant '{}' not found",
                grant_id
            )))
        }
    }

    /// Returns all currently active temporary capabilities for a workload
    pub fn get_active_capabilities_for_workload(
        &self,
        workload_id: &str,
        now_unix: i64,
    ) -> Vec<Capability> {
        let w_idx = self.workload_index.read().unwrap();
        let g_map = self.grants.read().unwrap();

        let mut active_caps = Vec::new();
        if let Some(grant_ids) = w_idx.get(workload_id) {
            for gid in grant_ids {
                if let Some(grant) = g_map.get(gid) {
                    if grant.is_active(now_unix) {
                        active_caps.push(grant.capability.clone());
                    }
                }
            }
        }
        active_caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temporary_capability_lifecycle() {
        let store = TemporaryCapabilityStore::new();
        let cap = Capability::FsWrite {
            path: "/tmp/backup".to_string(),
            append_only: true,
        };

        let grant = store
            .grant_temporary_capability(
                "tenant-1",
                "prn-1",
                "wkl-1",
                cap.clone(),
                60, // 60 seconds
                "Emergency log dump",
                Some("sec-admin"),
            )
            .unwrap();

        assert!(grant.is_active(grant.granted_at_unix + 10));
        assert!(!grant.is_active(grant.granted_at_unix + 61)); // Expired

        let active = store.get_active_capabilities_for_workload("wkl-1", grant.granted_at_unix + 10);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], cap);

        // Revocation test
        store.revoke_grant(&grant.grant_id).unwrap();
        assert!(!grant.is_active(grant.granted_at_unix + 10) || {
            let active_after = store.get_active_capabilities_for_workload("wkl-1", grant.granted_at_unix + 10);
            active_after.is_empty()
        });
    }
}
