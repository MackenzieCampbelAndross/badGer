import os
import subprocess

# Check if unshare(CLONE_NEWPID) without fork moves the calling process into a new PID namespace
import ctypes
libc = ctypes.CDLL(None)
CLONE_NEWPID = 0x20000000
CLONE_NEWNS = 0x00020000

res = libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
print("unshare result:", res)
print("Current PID:", os.getpid())
# Check /proc
pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
print(f"Total visible processes in /proc: {len(pids)}")
print(f"Can see init (PID 1): {1 in pids}")
if os.getpid() != 1:
    print("CONFIRMED VULNERABILITY: Process is NOT PID 1 and is NOT placed into an isolated PID namespace!")
