use aya::Bpf;
use aya::programs::TracePoint;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bpf_data = std::fs::read("/mnt/d/Mac/project/badger/tests/test_probe.bpf.o")?;
    let mut bpf = Bpf::load(&bpf_data)?;
    println!("[+] Successfully parsed eBPF object with Aya!");

    let program: &mut TracePoint = bpf.program_mut("handle_exec").unwrap().try_into()?;
    program.load()?;
    println!("[+] Successfully loaded eBPF program into Linux kernel!");

    program.attach("sched", "sched_process_exec")?;
    println!("[+] Successfully attached tracepoint sched/sched_process_exec to live Linux kernel!");

    Ok(())
}
