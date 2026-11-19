#!/usr/bin/env python3
"""
Independent PID Namespace & Procfs Verification Script for BADGER V1.0.1
Tests:
1. Namespace inode difference: readlink(/proc/self/ns/pid)
2. In-namespace PID is 1
3. Procfs isolation: host processes completely invisible
4. Signaling isolation: kill(host_pid, 0) fails
5. Process exit code forwarding and cleanup
"""

import os
import sys
import ctypes

CLONE_NEWPID = 0x20000000
CLONE_NEWNS  = 0x00020000
MS_NOSUID = 2
MS_NODEV  = 4
MS_NOEXEC = 8
MS_REC = 16384
MS_PRIVATE = 1 << 18

libc = ctypes.CDLL(None, use_errno=True)

def get_ns_id(pid="self", ns_type="pid"):
    try:
        return os.readlink(f"/proc/{pid}/ns/{ns_type}")
    except Exception as e:
        return f"error: {e}"

def main():
    print("=== BADGER V1.0.1 PID NAMESPACE DEEP VERIFICATION ===")
    host_pid_ns = get_ns_id("self", "pid")
    host_pid = os.getpid()
    print(f"[*] Host PID: {host_pid}")
    print(f"[*] Host PID Namespace: {host_pid_ns}")

    pipe_r, pipe_w = os.pipe()

    # Step 1: Simulate the exact BADGER sandbox pre-exec lifecycle
    parent_fork = os.fork()
    if parent_fork == 0:
        # Step A: unshare(CLONE_NEWNS | CLONE_NEWPID)
        res = libc.unshare(CLONE_NEWNS | CLONE_NEWPID)
        if res != 0:
            print(f"[FAIL] unshare failed: {ctypes.get_errno()}")
            sys.exit(1)

        # Step B: make mount private
        libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

        # Step C: fork child into new PID namespace
        child_pid = libc.fork()
        if child_pid < 0:
            print(f"[FAIL] fork into new PID namespace failed: {ctypes.get_errno()}")
            sys.exit(1)

        if child_pid > 0:
            # Intermediate parent (BADGER sandbox parent)
            # Waits for child and forwards exit code
            status = ctypes.c_int(0)
            libc.waitpid(child_pid, ctypes.byref(status), 0)
            exit_code = os.waitstatus_to_exitcode(status.value)
            libc._exit(exit_code)

        # --- Inside the Workload Child Process ---
        # Step D: Mount private procfs
        res = libc.mount(b"proc", b"/proc", b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
        if res != 0:
            err = ctypes.get_errno()
            msg = f"FAIL_MOUNT_PROC_{err}"
            os.write(pipe_w, msg.encode())
            sys.exit(1)

        # Step E: Inspect process state inside container
        inner_pid = os.getpid()
        inner_pid_ns = get_ns_id("self", "pid")
        visible_pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        
        # Test signaling host PID: should fail with ESRCH (No such process)
        can_signal_host = False
        try:
            os.kill(host_pid, 0)
            can_signal_host = True
        except ProcessLookupError:
            can_signal_host = False
        except Exception:
            can_signal_host = False

        report = f"INNER_PID={inner_pid};INNER_NS={inner_pid_ns};VISIBLE_COUNT={len(visible_pids)};CAN_SIGNAL_HOST={can_signal_host};VISIBLE_PIDS={visible_pids}"
        os.write(pipe_w, report.encode())
        os.close(pipe_w)
        sys.exit(42) # Custom exit code to verify forwarding

    os.close(pipe_w)
    raw_data = os.read(pipe_r, 4096).decode()
    os.close(pipe_r)

    _, status = os.waitpid(parent_fork, 0)
    actual_exit_code = os.waitstatus_to_exitcode(status)

    print(f"[*] Child reported: {raw_data}")
    data = dict(item.split("=", 1) for item in raw_data.split(";") if "=" in item)

    # 1. Verify in-namespace PID is 1
    if data.get("INNER_PID") == "1":
        print("[PASS] Workload sees itself as PID 1 inside new namespace.")
    else:
        print(f"[FAIL] Workload PID is {data.get('INNER_PID')}, expected 1!")

    # 2. Verify Namespace Inode differs
    inner_ns = data.get("INNER_NS")
    if inner_ns != host_pid_ns and "pid:" in inner_ns:
        print(f"[PASS] Inode confirmed isolated: Host ({host_pid_ns}) != Container ({inner_ns})")
    else:
        print(f"[FAIL] PID namespace inode matches host: {inner_ns}")

    # 3. Verify Procfs Visibility
    visible_count = int(data.get("VISIBLE_COUNT", 999))
    visible_pids = eval(data.get("VISIBLE_PIDS", "[]"))
    print(f"[*] Visible processes in container /proc: {visible_pids}")
    if visible_count <= 2 and all(p <= 2 for p in visible_pids):
        print(f"[PASS] Host /proc completely isolated! Only {visible_count} process(es) visible ({visible_pids}). Host processes concealed.")
    else:
        print(f"[FAIL] Container /proc leaked host processes! Count={visible_count}")

    # 4. Verify Signaling Isolation
    can_signal = data.get("CAN_SIGNAL_HOST") == "True"
    if not can_signal:
        print(f"[PASS] Cannot signal host process {host_pid} (ESRCH: Process not found in namespace).")
    else:
        print(f"[FAIL] Container could signal host PID {host_pid}!")

    # 5. Verify Exit Code Forwarding
    if actual_exit_code == 42:
        print(f"[PASS] Intermediate parent cleanly forwarded child exit status (Code: {actual_exit_code}).")
    else:
        print(f"[FAIL] Exit code forwarding failed: Expected 42, got {actual_exit_code}")

if __name__ == "__main__":
    main()
