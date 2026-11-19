import os
import sys
import ctypes

libc = ctypes.CDLL(None, use_errno=True)

CLONE_NEWPID = 0x20000000
CLONE_NEWNS = 0x00020000
MS_REC = 16384
MS_PRIVATE = 262144

# 1. Unshare namespaces
res = libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
print("unshare result:", res)

# 2. Make mounts private
res = libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
print("mount private result:", res)

# 3. Fork into new PID namespace
pid = os.fork()
if pid > 0:
    # Parent waits for child
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))

# In child: PID should be 1!
print(f"Child os.getpid(): {os.getpid()} (Expected: 1)")

# Mount fresh procfs
res = libc.mount(b"proc", b"/proc", b"proc", 0, None)
print("mount proc result:", res)

pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
print(f"PIDs visible in new procfs: {pids} (Expected: only [1])")
if os.getpid() == 1 and pids == [1]:
    print("SUCCESS: Full PID namespace isolation verified!")
else:
    print("FAILURE: PID namespace isolation incomplete!")
