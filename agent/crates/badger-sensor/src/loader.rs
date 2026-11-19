use badger_common::{BadgerError, BadgerResult};
use tracing::info;

pub const EBPF_BYTECODE: &[u8] = include_bytes!("../bpf/badger_telemetry.bpf.o");

pub struct ProbeLoader;

impl ProbeLoader {
    #[cfg(target_os = "linux")]
    pub fn load() -> BadgerResult<aya::Ebpf> {
        info!("Loading native eBPF telemetry bytecode ({} bytes)...", EBPF_BYTECODE.len());
        // ELF parsing requires proper memory alignment (Vec<u8> is guaranteed pointer-aligned)
        let aligned_bytecode = EBPF_BYTECODE.to_vec();
        aya::Ebpf::load(&aligned_bytecode).map_err(|e| {
            BadgerError::Sensor(format!("eBPF ELF parsing / verification failed: {:?}", e))
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load() -> BadgerResult<()> {
        Err(BadgerError::Sensor(
            "eBPF loader is only supported on Linux kernels".to_string(),
        ))
    }
}
