//! Integration tests for Badger Native eBPF Telemetry Subsystem.
//!
//! Validates:
//! 1. Kernel probe attachment and lifecycle.
//! 2. Live event capture from Linux kernel tracepoints.
//! 3. BPF ring buffer delivery and async event normalization.
//! 4. Workload attribution and provenance accounting.
//! 5. Capacity monitoring and capability health reporting.
//! 6. Microbenchmarks for kernel event capture and delivery latency.

use badger_common::{EventType, SensorHealthStatus};
use badger_sensor::bpf_types::{ProbeType, TelemetryCapabilityStatus};
use badger_sensor::{RuntimeSensor, SensorConfig};
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn test_ebpf_probe_attachment_and_lifecycle() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = SensorConfig {
            workload_id: "wkl-lifecycle-test".to_string(),
            principal_id: "prn-auditor".to_string(),
            target_pid: 0,
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, _rx) = RuntimeSensor::new(config);
        let start_res = sensor.start();
        assert!(start_res.is_ok(), "Sensor start failed: {:?}", start_res);

        // Verify capability and health reporting
        let health_report = sensor.get_health_report();
        assert_eq!(
            health_report.overall_status,
            SensorHealthStatus::Protected,
            "Sensor should report Protected when all eBPF probes attach on BTF kernel"
        );
        assert_eq!(health_report.process_telemetry, TelemetryCapabilityStatus::Active);
        assert_eq!(health_report.network_telemetry, TelemetryCapabilityStatus::Active);
        assert_eq!(health_report.filesystem_telemetry, TelemetryCapabilityStatus::Active);
        assert_eq!(health_report.privilege_telemetry, TelemetryCapabilityStatus::Active);
        assert_eq!(health_report.event_loss_count, 0);

        // Verify attached probes
        let attached = sensor.get_attached_probes();
        assert!(attached.contains(&ProbeType::ProcessExec));
        assert!(attached.contains(&ProbeType::ProcessExit));
        assert!(attached.contains(&ProbeType::ProcessFork));
        assert!(attached.contains(&ProbeType::NetworkConnect));
        assert!(attached.contains(&ProbeType::FilesystemOpen));
        assert!(attached.contains(&ProbeType::PrivilegeSetuid));

        // Graceful stop & probe detachment
        let stop_res = sensor.stop();
        assert!(stop_res.is_ok(), "Sensor stop failed: {:?}", stop_res);
        assert_eq!(sensor.get_health_status(), SensorHealthStatus::Unprotected);
        assert!(sensor.get_attached_probes().is_empty());
    });
}

#[test]
fn test_ebpf_live_process_exec_event_capture() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let workload_id = "wkl-exec-test";
        let config = SensorConfig {
            workload_id: workload_id.to_string(),
            principal_id: "prn-exec-agent".to_string(),
            target_pid: 0,
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, mut rx) = RuntimeSensor::new(config);
        sensor.start().expect("Failed to start sensor");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Spawn child process
        let child = Command::new("/bin/ls")
            .arg("/tmp")
            .spawn()
            .expect("Failed to spawn ls");
        let output = child.wait_with_output();
        assert!(output.is_ok());

        // Collect events delivered through BPF ring buffer
        let mut exec_found = false;
        let mut exit_found = false;
        let timeout = tokio::time::sleep(Duration::from_millis(2500));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(evt) => {
                            if evt.workload_id == workload_id {
                                if evt.event_type == EventType::ProcessExec && evt.resource.contains("ls") {
                                    exec_found = true;
                                    assert_eq!(evt.principal_id, "prn-exec-agent");
                                    assert_eq!(evt.sensor_provenance, "ebpf-tracepoint");
                                    assert!(evt.timestamp_unix_nanos > 0);
                                }
                                if evt.event_type == EventType::ProcessExit {
                                    exit_found = true;
                                }
                            }
                            if exec_found && exit_found {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        let _ = sensor.stop();
        assert!(exec_found, "Did not receive ProcessExec event for /bin/ls from BPF ring buffer");
        assert!(exit_found, "Did not receive ProcessExit event from BPF ring buffer");
    });
}

#[test]
fn test_ebpf_live_file_open_event_capture() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let workload_id = "wkl-file-test";
        let config = SensorConfig {
            workload_id: workload_id.to_string(),
            principal_id: "prn-file-agent".to_string(),
            target_pid: 0,
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, mut rx) = RuntimeSensor::new(config);
        sensor.start().expect("Failed to start sensor");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger file open in this target process
        let _ = std::fs::File::open("/etc/os-release");

        let mut file_open_found = false;
        let timeout = tokio::time::sleep(Duration::from_millis(2500));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(evt) => {
                            if evt.workload_id == workload_id && evt.event_type == EventType::FileOpen {
                                if evt.resource.contains("os-release") || !evt.resource.is_empty() {
                                    file_open_found = true;
                                    assert_eq!(evt.sensor_provenance, "ebpf-tracepoint");
                                    assert!(evt.attributes.contains_key("cpu_id"));
                                    assert!(evt.attributes.contains_key("cgroup_id"));
                                    break;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        let _ = sensor.stop();
        assert!(file_open_found, "Did not receive FileOpen event from BPF ring buffer");
    });
}

#[test]
fn test_ebpf_live_network_connect_event_capture() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let workload_id = "wkl-net-test";
        let config = SensorConfig {
            workload_id: workload_id.to_string(),
            principal_id: "prn-net-agent".to_string(),
            target_pid: 0,
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, mut rx) = RuntimeSensor::new(config);
        sensor.start().expect("Failed to start sensor");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attempt network connection (fires sys_enter_connect tracepoint)
        let _ = TcpStream::connect_timeout(
            &"127.0.0.1:49999".parse().unwrap(),
            Duration::from_millis(50),
        );

        let mut net_connect_found = false;
        let timeout = tokio::time::sleep(Duration::from_millis(2500));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(evt) => {
                            if evt.workload_id == workload_id && evt.event_type == EventType::NetConnect {
                                net_connect_found = true;
                                assert_eq!(evt.sensor_provenance, "ebpf-tracepoint");
                                assert_eq!(evt.resource, "af_inet");
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        let _ = sensor.stop();
        assert!(net_connect_found, "Did not receive NetConnect event from BPF ring buffer");
    });
}

#[test]
fn test_ebpf_latency_and_throughput_microbenchmark() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = SensorConfig {
            workload_id: "wkl-bench-test".to_string(),
            principal_id: "prn-bench".to_string(),
            target_pid: 0,
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, mut rx) = RuntimeSensor::new(config);
        sensor.start().expect("Failed to start sensor");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let iterations = 25;
        let mut latencies_us = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let t0 = Instant::now();
            let _ = std::fs::File::open("/etc/hosts");

            let timeout = tokio::time::sleep(Duration::from_millis(100));
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    res = rx.recv() => {
                        match res {
                            Ok(evt) => {
                                if evt.event_type == EventType::FileOpen && evt.resource.contains("hosts") {
                                    let elapsed = t0.elapsed().as_micros() as u64;
                                    latencies_us.push(elapsed);
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        }
                    }
                    _ = &mut timeout => {
                        break;
                    }
                }
            }
        }

        let _ = sensor.stop();

        assert!(!latencies_us.is_empty(), "Should capture at least 1 benchmark event");
        latencies_us.sort();
        let p50 = latencies_us[latencies_us.len() * 50 / 100];
        let p95 = latencies_us[latencies_us.len() * 95 / 100];
        let p99 = latencies_us[latencies_us.len() * 99 / 100];
        println!(
            "BADGER eBPF Benchmarks (N={}): P50={}µs, P95={}µs, P99={}µs",
            latencies_us.len(),
            p50,
            p95,
            p99
        );
        assert!(p50 < 50_000, "P50 latency should be under 50ms, was {}µs", p50);
    });
}
