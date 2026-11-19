use crate::capability::Capability;
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Typed delegation record representing authorized transfer of capabilities between principals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationGrant {
    pub grant_id: String,
    pub tenant_id: String,
    pub delegator_principal: String,
    pub delegatee_principal: String,
    pub delegated_capabilities: Vec<Capability>,
    pub resource_scope: String,
    pub delegation_depth: u32,
    pub granted_at_unix: i64,
    pub expires_at_unix: i64,
    pub is_revoked: bool,
}

pub struct DelegationGovernor {
    max_depth: u32,
    grants: Arc<RwLock<HashMap<String, DelegationGrant>>>,
}

impl Default for DelegationGovernor {
    fn default() -> Self {
        Self::new(2) // Default max delegation depth: 2 hops
    }
}

impl DelegationGovernor {
    pub fn new(max_depth: u32) -> Self {
        Self {
            max_depth,
            grants: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Evaluates and authorizes a capability delegation request.
    /// Strictly enforces capability intersection and maximum delegation depth.
    pub fn authorize_delegation(
        &self,
        tenant_id: &str,
        delegator: &str,
        delegatee: &str,
        requested_capabilities: Vec<Capability>,
        delegator_held_capabilities: &[Capability],
        current_depth: u32,
        duration_seconds: i64,
        resource_scope: &str,
    ) -> BadgerResult<DelegationGrant> {
        // 1. Enforce depth boundary
        let new_depth = current_depth + 1;
        if new_depth > self.max_depth {
            return Err(BadgerError::PolicyInvalid(format!(
                "Delegation denied: resulting depth {} exceeds maximum permitted depth {}",
                new_depth, self.max_depth
            )));
        }

        // 2. Prevent self-delegation loop
        if delegator == delegatee {
            return Err(BadgerError::PolicyInvalid(
                "Delegation denied: circular self-delegation prohibited".to_string(),
            ));
        }

        // 3. Enforce Capability Intersection:
        // The delegatee can only receive capabilities that are strictly subsumed by the delegator's held capabilities
        let mut validated_caps = Vec::new();
        for req_cap in requested_capabilities {
            let mut covered = false;
            for held_cap in delegator_held_capabilities {
                if held_cap.subsumes(&req_cap) {
                    covered = true;
                    validated_caps.push(req_cap.clone());
                    break;
                }
            }
            if !covered {
                return Err(BadgerError::PolicyInvalid(format!(
                    "Delegation denied (Capability Escalation): delegator '{}' does not possess capability '{:?}'",
                    delegator, req_cap
                )));
            }
        }

        let now = Utc::now().timestamp();
        let grant_id = format!("dlg_{}", Uuid::new_v4().simple());

        let grant = DelegationGrant {
            grant_id: grant_id.clone(),
            tenant_id: tenant_id.to_string(),
            delegator_principal: delegator.to_string(),
            delegatee_principal: delegatee.to_string(),
            delegated_capabilities: validated_caps,
            resource_scope: resource_scope.to_string(),
            delegation_depth: new_depth,
            granted_at_unix: now,
            expires_at_unix: now + duration_seconds,
            is_revoked: false,
        };

        let mut g_map = self.grants.write().unwrap();
        g_map.insert(grant_id, grant.clone());

        Ok(grant)
    }

    /// Revokes an existing delegation grant
    pub fn revoke_delegation(&self, grant_id: &str) -> BadgerResult<()> {
        let mut g_map = self.grants.write().unwrap();
        if let Some(grant) = g_map.get_mut(grant_id) {
            grant.is_revoked = true;
            Ok(())
        } else {
            Err(BadgerError::PolicyInvalid(format!(
                "Delegation grant '{}' not found",
                grant_id
            )))
        }
    }

    /// Returns active delegated capabilities for a delegatee principal
    pub fn get_active_delegated_capabilities(
        &self,
        delegatee: &str,
        now_unix: i64,
    ) -> Vec<Capability> {
        let g_map = self.grants.read().unwrap();
        let mut caps = Vec::new();

        for grant in g_map.values() {
            if grant.delegatee_principal == delegatee
                && !grant.is_revoked
                && now_unix <= grant.expires_at_unix
            {
                caps.extend(grant.delegated_capabilities.clone());
            }
        }
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_intersection_and_depth_limits() {
        let governor = DelegationGovernor::new(2);

        let held = vec![
            Capability::FsRead {
                path: "/workspace/data".to_string(),
                recursive: true,
            },
        ];

        // Valid delegation: subset of held capabilities
        let valid_req = vec![
            Capability::FsRead {
                path: "/workspace/data/reports.csv".to_string(),
                recursive: false,
            },
        ];
        let grant = governor
            .authorize_delegation(
                "tenant-1",
                "prn:orchestrator",
                "prn:worker-1",
                valid_req,
                &held,
                0,
                3600,
                "/workspace/data",
            )
            .unwrap();
        assert_eq!(grant.delegation_depth, 1);

        // Escalation attempt: requesting /etc/passwd which is not in held capabilities -> must be rejected
        let invalid_req = vec![
            Capability::FsRead {
                path: "/etc/passwd".to_string(),
                recursive: false,
            },
        ];
        let res_escalation = governor.authorize_delegation(
            "tenant-1",
            "prn:orchestrator",
            "prn:worker-1",
            invalid_req,
            &held,
            0,
            3600,
            "*",
        );
        assert!(res_escalation.is_err(), "Must block capability escalation attempt");

        // Excessive depth attempt: depth 2 -> 3 exceeds limit 2 -> must be rejected
        let res_depth = governor.authorize_delegation(
            "tenant-1",
            "prn:worker-1",
            "prn:sub-worker",
            vec![Capability::FsRead {
                path: "/workspace/data".to_string(),
                recursive: true,
            }],
            &held,
            2,
            3600,
            "/workspace/data",
        );
        assert!(res_depth.is_err(), "Must block delegation depth > max_depth");
    }
}
