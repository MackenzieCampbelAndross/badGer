use crate::types::{NetworkAction, NetworkDecisionEvent, NetworkStats};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

pub const MAX_TELEMETRY_HISTORY: usize = 1000;

#[derive(Debug, Clone)]
pub struct NetworkTelemetryRegistry {
    events: Arc<RwLock<VecDeque<NetworkDecisionEvent>>>,
    stats: Arc<RwLock<NetworkStats>>,
}

impl Default for NetworkTelemetryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTelemetryRegistry {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_TELEMETRY_HISTORY))),
            stats: Arc::new(RwLock::new(NetworkStats::default())),
        }
    }

    pub fn record_event(&self, event: NetworkDecisionEvent) {
        let is_denied = event.action == NetworkAction::Deny;

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_connections += 1;
            if is_denied {
                stats.denied_connections += 1;
                stats.violations_count += 1;
            } else {
                stats.allowed_connections += 1;
            }
        }

        // Record in circular buffer
        {
            let mut events = self.events.write().unwrap();
            if events.len() >= MAX_TELEMETRY_HISTORY {
                events.pop_front();
            }
            events.push_back(event);
        }
    }

    pub fn get_recent_events(
        &self,
        limit: usize,
        action_filter: Option<NetworkAction>,
    ) -> Vec<NetworkDecisionEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .rev()
            .filter(|e| {
                if let Some(act) = action_filter {
                    e.action == act
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_stats(&self) -> NetworkStats {
        self.stats.read().unwrap().clone()
    }

    pub fn clear(&self) {
        self.events.write().unwrap().clear();
        *self.stats.write().unwrap() = NetworkStats::default();
    }
}
