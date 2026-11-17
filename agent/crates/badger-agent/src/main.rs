pub mod adversarial;
pub mod benchmarks;

use adversarial::AdversarialRunner;
use badger_common::{
    AuditLogger, CapabilityPolicy, FilesystemRule, FsAccess, NetworkRule, PrincipalType,
    ResourceLimits,
};
use badger_containment::ContainmentEngine;
use badger_identity::{IdentityStore, WorkloadRegistration};
use badger_policy::PolicyEngine;
use badger_sandbox::{LinuxSandbox, SandboxConfig};
use badger_sensor::{RuntimeSensor, SensorConfig};
use benchmarks::BenchmarkHarness;
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "badger-agent")]
#[command(about = "BADGER: Autonomous Agent Security & Runtime Containment Infrastructure")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a workload inside the BADGER Linux sandbox
    Run {
        #[arg(short, long)]
        workload: String,

        #[arg(short, long)]
        policy: Option<PathBuf>,

        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Run the required adversarial security scenarios (A through H)
    Adversarial {
        #[arg(short, long)]
        scenario: Option<String>,
    },

    /// Run performance and throughput benchmarks
    Benchmark,

    /// Verify tamper-evident cryptographic hash chain of audit records
    VerifyAudit {
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            workload,
            policy: policy_path,
            command,
        } => {
            if command.is_empty() {
                eprintln!("Error: No command specified to run.");
                std::process::exit(1);
            }

            println!("============================================================");
            println!("  BADGER V1.0 - RUNTIME CONTAINMENT ENGINE");
            println!("============================================================");

            let identity_store = IdentityStore::new();
            identity_store.register_tenant("default", "Default Organization")?;
            let principal = identity_store.register_principal(
                "default",
                "autonomous-agent",
                PrincipalType::Agent,
                HashMap::new(),
            )?;

            let policy = if let Some(path) = policy_path {
                let content = fs::read_to_string(path)?;
                serde_json::from_str(&content)?
            } else {
                CapabilityPolicy {
                    id: "pol-default".to_string(),
                    tenant_id: "default".to_string(),
                    name: "Default Agent Policy".to_string(),
                    version: 1,
                    allowed_executables: vec![command[0].clone()],
                    denied_executables: vec!["/bin/nc".to_string()],
                    filesystem_rules: vec![FilesystemRule {
                        path: ".".to_string(),
                        access: FsAccess::Rw,
                        recursive: true,
                    }],
                    network_rules: vec![NetworkRule {
                        destination: "127.0.0.1".to_string(),
                        port: 8080,
                        protocol: "tcp".to_string(),
                        allow: true,
                    }],
                    limits: ResourceLimits::default(),
                    drop_capabilities: vec!["CAP_SYS_ADMIN".to_string()],
                    disallow_privilege_escalation: true,
                    valid_from_unix: 0,
                    valid_until_unix: Utc::now().timestamp() + 86400,
                    signature: String::new(),
                }
            };

            let policy_engine = PolicyEngine::new("default-key");
            policy_engine.load_policy(policy.clone())?;

            let reg = identity_store.register_workload(WorkloadRegistration {
                tenant_id: "default".to_string(),
                principal_id: principal.id,
                workload_name: workload,
                policy_id: policy.id.clone(),
                policy_version: policy.version,
                metadata: HashMap::new(),
            })?;

            println!("[+] Workload Registered:");
            println!("    ID:        {}", reg.id);
            println!("    Principal: {}", reg.principal_id);
            println!("    SPIFFE ID: {}", reg.metadata.get("spiffe_id").unwrap());

            let audit_logger = Arc::new(AuditLogger::default());
            let _containment = ContainmentEngine::new(audit_logger.clone());

            let sandbox = LinuxSandbox::new(SandboxConfig {
                workload_id: reg.id.clone(),
                policy,
                isolate_network: true,
            });

            sandbox.prepare()?;
            println!("[+] Sandbox Isolation Boundaries Configured (cgroups v2, Landlock, Seccomp, Namespaces)");

            let (sensor, _rx) = RuntimeSensor::new(SensorConfig {
                workload_id: reg.id.clone(),
                principal_id: reg.principal_id.clone(),
                target_pid: std::process::id(),
                enable_ebpf: true,
            });
            sensor.start()?;
            println!("[+] Telemetry Sensor Active. Health: {:?}", sensor.get_health_status());

            let prog = &command[0];
            let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();

            println!("[+] Launching: {} {:?}", prog, args);
            match sandbox.spawn(prog, &args) {
                Ok(mut child) => {
                    let status = child.wait()?;
                    println!("[+] Workload Completed. Exit status: {}", status);
                }
                Err(e) => {
                    eprintln!("[-] Containment Enforcement Blocked Execution: {}", e);
                }
            }

            sandbox.cleanup();
        }

        Commands::Adversarial { scenario } => {
            let runner = AdversarialRunner::new();
            println!("============================================================");
            println!("  BADGER V1.0 - ADVERSARIAL VERIFICATION SUITE");
            println!("============================================================");

            let scenarios = match scenario.as_deref() {
                Some("A") | Some("a") => vec![runner.run_scenario_a()?],
                Some("B") | Some("b") => vec![runner.run_scenario_b()?],
                Some("C") | Some("c") => vec![runner.run_scenario_c()?],
                Some("D") | Some("d") => vec![runner.run_scenario_d()?],
                Some("E") | Some("e") => vec![runner.run_scenario_e()?],
                Some("F") | Some("f") => vec![runner.run_scenario_f()?],
                Some("G") | Some("g") => vec![runner.run_scenario_g()?],
                Some("H") | Some("h") => vec![runner.run_scenario_h()?],
                _ => vec![
                    runner.run_scenario_a()?,
                    runner.run_scenario_b()?,
                    runner.run_scenario_c()?,
                    runner.run_scenario_d()?,
                    runner.run_scenario_e()?,
                    runner.run_scenario_f()?,
                    runner.run_scenario_g()?,
                    runner.run_scenario_h()?,
                ],
            };

            println!("\n| Scenario | Detection | Enforcement | Audit | Verified | Result |");
            println!("|---|---|---|---|---|---|");
            for s in scenarios {
                let status_icon = if s.verification_succeeded { "PASS" } else { "FAIL" };
                println!(
                    "| {} | {} | {} | {} | {} | {} |",
                    s.scenario,
                    if s.detection_succeeded { "YES" } else { "NO" },
                    if s.enforcement_succeeded { "YES" } else { "NO" },
                    if s.audit_recorded { "YES" } else { "NO" },
                    if s.verification_succeeded { "YES" } else { "NO" },
                    status_icon
                );
            }
        }

        Commands::Benchmark => {
            println!("============================================================");
            println!("  BADGER V1.0 - PERFORMANCE BENCHMARK HARNESS");
            println!("============================================================");
            println!("[*] Running 10,000 policy & event evaluation cycles...");
            let rep = BenchmarkHarness::run();

            println!("\nBenchmark Results (10,000 iterations):");
            println!("  Policy Evaluation Latency:");
            println!("    P50: {:>8.3} µs", rep.policy_eval_p50_us);
            println!("    P95: {:>8.3} µs", rep.policy_eval_p95_us);
            println!("    P99: {:>8.3} µs", rep.policy_eval_p99_us);
            println!("  Threat Detection Latency:");
            println!("    P50: {:>8.3} µs", rep.threat_eval_p50_us);
            println!("    P95: {:>8.3} µs", rep.threat_eval_p95_us);
            println!("    P99: {:>8.3} µs", rep.threat_eval_p99_us);
            println!("  Event Processing Throughput: {:>10.0} events/second", rep.event_ingest_throughput_eps);
            println!("  Event Loss Under Load:       {:>8.2}%", rep.event_loss_percentage);
        }

        Commands::VerifyAudit { file } => {
            println!("Verifying tamper-evident audit records...");
            if let Some(path) = file {
                let content = fs::read_to_string(path)?;
                let records: Vec<badger_common::AuditRecord> = serde_json::from_str(&content)?;
                let valid = AuditLogger::verify_chain(&records);
                if valid {
                    println!("[PASS] Audit log cryptographic hash chain is valid and untampered.");
                } else {
                    eprintln!("[FAIL] Audit log cryptographic hash chain validation FAILED!");
                    std::process::exit(1);
                }
            } else {
                println!("No audit log file specified. Use --file <path> to verify an audit trail.");
            }
        }
    }

    Ok(())
}
