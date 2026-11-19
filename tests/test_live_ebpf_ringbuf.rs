use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BadgerBpfEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub host_pid: u32,
    pub host_tid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cpu_id: u32,
    pub event_type: u32,
    pub comm: [u8; 16],
    pub resource: [u8; 128],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TESTING NATIVE eBPF TRACEPOINTS + RING BUFFER IN LINUX ===");
    let bpf_bytes = std::fs::read("/mnt/d/Mac/project/badger/tests/test_multi_probe.bpf.o")?;
    let mut ebpf = Ebpf::load(&bpf_bytes)?;
    println!("[+] Parsed multi-probe eBPF ELF with Aya!");

    // Attach all 6 tracepoints
    let probes = [
        ("handle_process_exec", "sched", "sched_process_exec"),
        ("handle_process_exit", "sched", "sched_process_exit"),
        ("handle_process_fork", "sched", "sched_process_fork"),
        ("handle_sys_connect", "syscalls", "sys_enter_connect"),
        ("handle_sys_openat", "syscalls", "sys_enter_openat"),
        ("handle_sys_setuid", "syscalls", "sys_enter_setuid"),
    ];

    for (prog_name, category, tp_name) in &probes {
        let prog: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| format!("Program {} not found", prog_name))?
            .try_into()?;
        prog.load()?;
        prog.attach(category, tp_name)?;
        println!("[+] Attached tracepoint {}/{} successfully!", category, tp_name);
    }

    // Access RingBuf map
    let ringbuf_map = ebpf.take_map("events_ringbuf").expect("events_ringbuf map not found");
    let mut ring_buf = RingBuf::try_from(ringbuf_map)?;
    println!("[+] BPF Ring Buffer initialized successfully (capacity: 256KB)!");

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    // Spawn a background thread to read events from the BPF ring buffer
    let handle = std::thread::spawn(move || {
        let mut count = 0;
        println!("[*] Ring buffer polling loop active...");
        while r_clone.load(Ordering::SeqCst) {
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<BadgerBpfEvent>() {
                    let event: BadgerBpfEvent = unsafe { std::ptr::read(item.as_ptr() as *const _) };
                    let comm = String::from_utf8_lossy(&event.comm).trim_matches('\0').to_string();
                    let res = String::from_utf8_lossy(&event.resource).trim_matches('\0').to_string();
                    let type_str = match event.event_type {
                        1 => "EXEC",
                        2 => "EXIT",
                        3 => "FORK",
                        4 => "CONNECT",
                        5 => "SETUID",
                        6 => "OPENAT",
                        _ => "OTHER",
                    };
                    println!(
                        "    [KERNEL EVENT #{}]: Type={} PID={} TGID={} Cgroup={} CPU={} Comm='{}' Resource='{}'",
                        count + 1, type_str, event.host_tid, event.host_pid, event.cgroup_id, event.cpu_id, comm, res
                    );
                    count += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        count
    });

    // Trigger real workload events in userspace to be intercepted by our kernel probes!
    println!("[*] Triggering live OS events (executing /bin/ls)...");
    let _ = std::process::Command::new("/bin/ls").arg("/tmp").output();

    // Sleep 500ms to allow kernel tracepoints to deliver events into ringbuf
    std::thread::sleep(Duration::from_millis(500));

    running.store(false, Ordering::SeqCst);
    let total_events = handle.join().unwrap();
    println!("[+] Total kernel events successfully delivered via Ring Buffer: {}", total_events);
    assert!(total_events > 0, "Expected at least 1 real kernel event!");

    println!("=== NATIVE eBPF VERIFICATION SUCCESSFUL ===");
    Ok(())
}
