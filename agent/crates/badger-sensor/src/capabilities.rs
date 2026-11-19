use std::path::Path;
use tracing::info;

#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub has_btf: bool,
    pub has_tracepoints: bool,
    pub has_cgroup2: bool,
    pub is_linux: bool,
    pub kernel_release: String,
    pub supports_ebpf: bool,
}

pub struct KernelCapabilityDetector;

impl KernelCapabilityDetector {
    pub fn detect() -> KernelCapabilities {
        if !cfg!(target_os = "linux") {
            return KernelCapabilities {
                has_btf: false,
                has_tracepoints: false,
                has_cgroup2: false,
                is_linux: false,
                kernel_release: "Non-Linux".to_string(),
                supports_ebpf: false,
            };
        }

        let has_btf = Path::new("/sys/kernel/btf/vmlinux").exists();
        let has_tracepoints = Path::new("/sys/kernel/debug/tracing/events").exists()
            || Path::new("/sys/kernel/tracing/events").exists();
        let has_cgroup2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
            || Path::new("/sys/fs/cgroup/cgroup.procs").exists();

        let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        let supports_ebpf = has_btf && has_tracepoints;

        info!(
            "Kernel Capability Detection: release='{}', BTF={}, tracepoints={}, cgroup2={}, eBPF_ready={}",
            kernel_release, has_btf, has_tracepoints, has_cgroup2, supports_ebpf
        );

        KernelCapabilities {
            has_btf,
            has_tracepoints,
            has_cgroup2,
            is_linux: true,
            kernel_release,
            supports_ebpf,
        }
    }
}
