use crate::types::RiskAssessment;
use chrono::Utc;
use std::collections::HashMap;

pub struct IntegratedRiskEngine;

impl IntegratedRiskEngine {
    /// Computes a deterministic, fully explainable risk assessment for a workload.
    /// Strictly avoids arbitrary, unexplained numbers by documenting every contributing factor.
    pub fn evaluate_risk(
        workload_id: &str,
        workload_criticality: &str, // "Critical", "High", "Medium", "Low"
        finding_severities: &[(&str, f32)], // (severity, confidence)
        has_network_violations: bool,
        has_over_privileged_access: bool,
        sensitive_credentials_count: usize,
    ) -> RiskAssessment {
        let mut score: u32 = 0;
        let mut factors = Vec::new();
        let mut evidence = HashMap::new();

        // 1. Workload Criticality Impact
        match workload_criticality {
            "Critical" => {
                score += 25;
                factors.push("Critical workload tier: high blast radius if compromised (+25)".to_string());
                evidence.insert("criticality".to_string(), "Critical".to_string());
            }
            "High" => {
                score += 15;
                factors.push("High workload tier (+15)".to_string());
                evidence.insert("criticality".to_string(), "High".to_string());
            }
            "Medium" => {
                score += 5;
                factors.push("Medium workload tier (+5)".to_string());
                evidence.insert("criticality".to_string(), "Medium".to_string());
            }
            _ => {}
        }

        // 2. Security Findings Impact (scaled by confidence)
        let mut findings_score = 0;
        for (sev, conf) in finding_severities {
            let base = match *sev {
                "Critical" => 40,
                "High" => 25,
                "Medium" => 12,
                _ => 5,
            };
            let weighted = (base as f32 * conf) as u32;
            findings_score += weighted;
            factors.push(format!(
                "Active {} finding with {:.0}% confidence (+{})",
                sev, conf * 100.0, weighted
            ));
        }
        score += findings_score.min(50);
        evidence.insert("findings_count".to_string(), finding_severities.len().to_string());

        // 3. Network Egress Violations
        if has_network_violations {
            score += 20;
            factors.push("Kernel observed network egress violations (+20)".to_string());
            evidence.insert("network_violations".to_string(), "true".to_string());
        }

        // 4. Over-Privileged Identity Posture
        if has_over_privileged_access {
            score += 15;
            factors.push("Over-privileged identity: granted access exceeds observed behavior (+15)".to_string());
            evidence.insert("over_privileged".to_string(), "true".to_string());
        }

        // 5. Sensitive Credentials Exposure
        if sensitive_credentials_count > 0 {
            let cred_points = (sensitive_credentials_count as u32 * 5).min(15);
            score += cred_points;
            factors.push(format!(
                "{} sensitive credentials bound to workload (+{})",
                sensitive_credentials_count, cred_points
            ));
            evidence.insert("sensitive_credentials".to_string(), sensitive_credentials_count.to_string());
        }

        let final_score = (score.min(100)) as u8;

        let severity = if final_score >= 80 {
            "Critical"
        } else if final_score >= 60 {
            "High"
        } else if final_score >= 30 {
            "Medium"
        } else {
            "Low"
        };

        evidence.insert("final_score".to_string(), final_score.to_string());
        evidence.insert("severity".to_string(), severity.to_string());

        RiskAssessment {
            workload_id: workload_id.to_string(),
            risk_score: final_score,
            severity: severity.to_string(),
            contributing_factors: factors,
            evidence,
            evaluated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explainable_risk_calculation() {
        let assessment = IntegratedRiskEngine::evaluate_risk(
            "wkl-101",
            "Critical",
            &[("Critical", 1.0)],
            true,
            true,
            2,
        );

        assert!(assessment.risk_score >= 80);
        assert_eq!(assessment.severity, "Critical");
        assert!(!assessment.contributing_factors.is_empty());
        assert!(assessment.contributing_factors.iter().any(|f| f.contains("Critical workload tier")));
    }
}
