use badger_network::{
    NetworkAction, NetworkEnforcer, NetworkPolicy, NetworkProtocol, NetworkRule,
};
use std::fs;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Instant;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn setup_test_cgroup(name: &str) -> PathBuf {
    let base = PathBuf::from("/sys/fs/cgroup/badger");
    let cgroup = base.join(name);
    let _ = fs::create_dir_all(&cgroup);
    cgroup
}

fn enter_cgroup(cgroup: &PathBuf) -> std::io::Result<()> {
    let procs = cgroup.join("cgroup.procs");
    fs::write(procs, format!("{}\n", std::process::id()))
}

fn exit_cgroup() {
    let root_procs = PathBuf::from("/sys/fs/cgroup/cgroup.procs");
    let _ = fs::write(root_procs, format!("{}\n", std::process::id()));
}

#[test]
#[cfg(target_os = "linux")]
fn test_kernel_network_egress_allow_and_block_tcp() {
    let _lock = TEST_LOCK.lock().unwrap();
    let cgroup_path = setup_test_cgroup("test_net_tcp");
    let workload_id = "wkl_test_net_tcp";

    // Bind two test servers on local interface
    let listener_allowed = TcpListener::bind("127.0.0.1:19101").expect("Failed to bind allowed listener");
    let listener_denied = TcpListener::bind("127.0.0.1:19102").expect("Failed to bind denied listener");

    // Spawn accepting threads
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener_allowed.accept() {
            drop(stream);
        }
    });
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener_denied.accept() {
            drop(stream);
        }
    });

    // Policy: Allow port 19101, Deny port 19102, Default Deny, Cloud Metadata Blocked
    let policy = NetworkPolicy {
        id: "pol-test-1".to_string(),
        tenant_id: "tenant-test".to_string(),
        workload_id: workload_id.to_string(),
        version: 1,
        default_action: NetworkAction::Deny,
        block_cloud_metadata: true,
        rules: vec![
            NetworkRule::new_allow(101, "127.0.0.1/32", 19101, NetworkProtocol::Tcp),
            NetworkRule::new_deny(102, "127.0.0.1/32", 19102, NetworkProtocol::Tcp),
        ],
        valid_from_unix: 0,
        valid_until_unix: 0,
        signature: "valid-sig".to_string(),
        issuer: "test".to_string(),
    };

    let enforcer = NetworkEnforcer::new(workload_id, cgroup_path.clone());
    enforcer.attach(&policy).expect("Failed to attach network enforcer to cgroup");

    // Enter cgroup
    enter_cgroup(&cgroup_path).expect("Failed to enter cgroup");

    // 1. Connection to allowed destination port 19101 MUST SUCCEED
    let conn_allowed = TcpStream::connect("127.0.0.1:19101");
    assert!(
        conn_allowed.is_ok(),
        "Expected allowed connection to port 19101 to succeed, got: {:?}",
        conn_allowed.err()
    );

    // 2. Connection to explicitly denied destination port 19102 MUST FAIL at OS kernel boundary with EPERM
    let conn_denied = TcpStream::connect("127.0.0.1:19102");
    assert!(
        conn_denied.is_err(),
        "Expected denied connection to port 19102 to fail at kernel boundary"
    );
    let err = conn_denied.err().unwrap();
    assert_eq!(
        err.kind(),
        ErrorKind::PermissionDenied,
        "Expected PermissionDenied (EPERM), got: {:?}",
        err
    );

    // 3. Connection to unlisted destination port (Default Deny) MUST FAIL with EPERM
    let conn_default_denied = TcpStream::connect("127.0.0.1:19199");
    assert!(conn_default_denied.is_err());
    assert_eq!(
        conn_default_denied.err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );

    // 4. Connection to cloud metadata endpoint (169.254.169.254) MUST FAIL with EPERM
    let conn_metadata = TcpStream::connect("169.254.169.254:80");
    assert!(conn_metadata.is_err());
    assert_eq!(
        conn_metadata.err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );

    // Exit cgroup & detach
    exit_cgroup();
    enforcer.detach().expect("Failed to detach enforcer");
}

#[test]
#[cfg(target_os = "linux")]
fn test_kernel_dynamic_policy_update_during_execution() {
    let _lock = TEST_LOCK.lock().unwrap();
    let cgroup_path = setup_test_cgroup("test_net_dynamic");
    let workload_id = "wkl_test_net_dynamic";

    let listener = TcpListener::bind("127.0.0.1:19201").expect("Failed to bind listener");
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Policy v1: Denies port 19201
    let policy_v1 = NetworkPolicy {
        id: "pol-dyn-1".to_string(),
        tenant_id: "tenant-test".to_string(),
        workload_id: workload_id.to_string(),
        version: 1,
        default_action: NetworkAction::Deny,
        block_cloud_metadata: true,
        rules: vec![
            NetworkRule::new_deny(201, "127.0.0.1/32", 19201, NetworkProtocol::Tcp),
        ],
        valid_from_unix: 0,
        valid_until_unix: 0,
        signature: "sig1".to_string(),
        issuer: "test".to_string(),
    };

    let enforcer = NetworkEnforcer::new(workload_id, cgroup_path.clone());
    enforcer.attach(&policy_v1).expect("Failed to attach enforcer");

    enter_cgroup(&cgroup_path).expect("Failed to enter cgroup");

    // Attempt 1: Port 19201 is BLOCKED with EPERM under Policy v1
    let conn1 = TcpStream::connect("127.0.0.1:19201");
    assert!(conn1.is_err());
    assert_eq!(conn1.err().unwrap().kind(), ErrorKind::PermissionDenied);

    // Policy v2: Dynamically allow port 19201 without detaching or restarting
    let policy_v2 = NetworkPolicy {
        id: "pol-dyn-1".to_string(),
        tenant_id: "tenant-test".to_string(),
        workload_id: workload_id.to_string(),
        version: 2,
        default_action: NetworkAction::Deny,
        block_cloud_metadata: true,
        rules: vec![
            NetworkRule::new_allow(201, "127.0.0.1/32", 19201, NetworkProtocol::Tcp),
        ],
        valid_from_unix: 0,
        valid_until_unix: 0,
        signature: "sig2".to_string(),
        issuer: "test".to_string(),
    };

    enforcer.update_policy(&policy_v2).expect("Failed to dynamically update policy");

    // Small yield to let map update settle
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Attempt 2: Port 19201 is NOW ALLOWED under Policy v2
    let conn2 = TcpStream::connect("127.0.0.1:19201");
    assert!(
        conn2.is_ok(),
        "Expected dynamic policy update to allow port 19201, got: {:?}",
        conn2.err()
    );

    exit_cgroup();
    enforcer.detach().expect("Failed to detach enforcer");
}

#[test]
#[cfg(target_os = "linux")]
fn test_kernel_udp_sendmsg_enforcement() {
    let _lock = TEST_LOCK.lock().unwrap();
    let cgroup_path = setup_test_cgroup("test_net_udp");
    let workload_id = "wkl_test_net_udp";

    let _socket_allowed = UdpSocket::bind("127.0.0.1:19301").expect("Failed to bind UDP allowed");
    let _socket_denied = UdpSocket::bind("127.0.0.1:19302").expect("Failed to bind UDP denied");

    let policy = NetworkPolicy {
        id: "pol-udp-1".to_string(),
        tenant_id: "tenant-test".to_string(),
        workload_id: workload_id.to_string(),
        version: 1,
        default_action: NetworkAction::Deny,
        block_cloud_metadata: true,
        rules: vec![
            NetworkRule::new_allow(301, "127.0.0.1/32", 19301, NetworkProtocol::Udp),
            NetworkRule::new_deny(302, "127.0.0.1/32", 19302, NetworkProtocol::Udp),
        ],
        valid_from_unix: 0,
        valid_until_unix: 0,
        signature: "sig".to_string(),
        issuer: "test".to_string(),
    };

    let enforcer = NetworkEnforcer::new(workload_id, cgroup_path.clone());
    enforcer.attach(&policy).expect("Failed to attach enforcer");

    enter_cgroup(&cgroup_path).expect("Failed to enter cgroup");

    let client_sock = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client UDP socket");

    // 1. Sendto allowed UDP port 19301 -> SUCCEEDS
    let res_allowed = client_sock.send_to(b"ping_allow", "127.0.0.1:19301");
    assert!(
        res_allowed.is_ok(),
        "Expected allowed UDP send_to to succeed, got: {:?}",
        res_allowed.err()
    );

    // 2. Sendto denied UDP port 19302 -> FAILS with EPERM
    let res_denied = client_sock.send_to(b"ping_deny", "127.0.0.1:19302");
    assert!(res_denied.is_err());
    assert_eq!(
        res_denied.err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );

    exit_cgroup();
    enforcer.detach().expect("Failed to detach enforcer");
}

#[test]
#[cfg(target_os = "linux")]
fn test_kernel_network_accounting_and_benchmarks() {
    let _lock = TEST_LOCK.lock().unwrap();
    let cgroup_path = setup_test_cgroup("test_net_bench");
    let workload_id = "wkl_test_net_bench";

    let listener = TcpListener::bind("127.0.0.1:19401").expect("Failed to bind listener");
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    let policy = NetworkPolicy {
        id: "pol-bench".to_string(),
        tenant_id: "tenant-test".to_string(),
        workload_id: workload_id.to_string(),
        version: 1,
        default_action: NetworkAction::Deny,
        block_cloud_metadata: true,
        rules: vec![
            NetworkRule::new_allow(401, "127.0.0.1/32", 19401, NetworkProtocol::Tcp),
        ],
        valid_from_unix: 0,
        valid_until_unix: 0,
        signature: "sig".to_string(),
        issuer: "test".to_string(),
    };

    let enforcer = NetworkEnforcer::new(workload_id, cgroup_path.clone());
    enforcer.attach(&policy).expect("Failed to attach enforcer");

    enter_cgroup(&cgroup_path).expect("Failed to enter cgroup");

    // Benchmark connection decision latency
    let iterations = 30;
    let mut latencies_us = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = Instant::now();
        let _ = TcpStream::connect("127.0.0.1:19401");
        latencies_us.push(t0.elapsed().as_micros());
    }

    latencies_us.sort();
    let p50 = latencies_us[iterations / 2];
    let p95 = latencies_us[(iterations * 95) / 100];
    let p99 = latencies_us[iterations - 1];

    println!(
        "BADGER Phase 2 Kernel Network Latency (N={}): P50={}µs, P95={}µs, P99={}µs",
        iterations, p50, p95, p99
    );

    // Verify stats map accounting
    let stats = enforcer.get_stats();
    assert!(stats.total_connections >= iterations as u64);
    assert!(stats.allowed_connections >= iterations as u64);

    exit_cgroup();
    enforcer.detach().expect("Failed to detach enforcer");
}
