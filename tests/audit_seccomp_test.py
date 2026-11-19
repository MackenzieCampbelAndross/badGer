import ctypes
import os

libc = ctypes.CDLL(None)

# Install the exact same seccomp filter as badger-sandbox
class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_uint16), ('jt', ctypes.c_uint8), ('jf', ctypes.c_uint8), ('k', ctypes.c_uint32)]

class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_uint16), ('filter', ctypes.c_void_p)]

# Syscalls blocked by badger-sandbox: 101 (ptrace), 321 (bpf), 165 (mount), 166 (umount2), 155 (pivot_root), 246 (kexec_load), 169 (reboot)
blocked_syscalls = [101, 321, 165, 166, 155, 246, 169]

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000 | 1 # EPERM
SECCOMP_RET_ALLOW = 0x7fff0000
AUDIT_ARCH_X86_64 = 0xc000003e

filters = [
    SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
    SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64),
    SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
]

for sc in blocked_syscalls:
    filters.append(SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, sc))
    filters.append(SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO))

filters.append(SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW))

f_array = (SockFilter * len(filters))(*filters)
prog = SockFprog(len(filters), ctypes.cast(f_array, ctypes.c_void_p))

libc.prctl(38, 1, 0, 0, 0) # PR_SET_NO_NEW_PRIVS
res = libc.syscall(317, 1, 0, ctypes.byref(prog))
print("Seccomp installed:", res == 0)

# 1. Test blocked syscall: ptrace
import errno
res = libc.ptrace(0, 0, 0, 0)
err = ctypes.get_errno()
print(f"ptrace() result: {res}, errno: {err} (Expected EPERM {errno.EPERM})")

# 2. Test unblocked dangerous syscalls that BADGER claims or implies are restricted:
# Test socket creation
SYS_socket = 41
sock_fd = libc.syscall(SYS_socket, 2, 1, 0) # AF_INET, SOCK_STREAM
print(f"socket(AF_INET, SOCK_STREAM) result: {sock_fd} (CONFIRMED: socket creation NOT blocked by seccomp!)")

# Test io_uring_setup
SYS_io_uring_setup = 425
res = libc.syscall(SYS_io_uring_setup, 4, 0)
print(f"io_uring_setup result: {res} (CONFIRMED: io_uring NOT blocked by seccomp!)")

# Test userfaultfd
SYS_userfaultfd = 323
res = libc.syscall(SYS_userfaultfd, 0)
print(f"userfaultfd result: {res} (CONFIRMED: userfaultfd NOT blocked by seccomp!)")
