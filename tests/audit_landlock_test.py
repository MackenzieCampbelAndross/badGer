import ctypes
import os

SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446

libc = ctypes.CDLL(None, use_errno=True)

class RulesetAttr(ctypes.Structure):
    _fields_ = [('handled_access_fs', ctypes.c_uint64)]

class PathBeneathAttr(ctypes.Structure):
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3

PR_SET_NO_NEW_PRIVS = 38
libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

attr = RulesetAttr((1 << 13) - 1)
ruleset_fd = libc.syscall(SYS_landlock_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
print('ruleset_fd:', ruleset_fd)

for p in ['/bin', '/usr', '/lib', '/lib64', '/etc']:
    try:
        fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
        pb = PathBeneathAttr(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE, fd)
        res = libc.syscall(SYS_landlock_add_rule, ruleset_fd, 1, ctypes.byref(pb), 0)
        os.close(fd)
    except Exception as e:
        print(f"Skipping {p}: {e}")

# Note: /etc/shadow is omitted (as in LandlockEnforcer when access == 'none')
res = libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
os.close(ruleset_fd)
print('restrict_self result:', res)

try:
    with open('/etc/shadow', 'r') as f:
        print('CRITICAL VULNERABILITY CONFIRMED: Successfully opened /etc/shadow!')
        print('First line:', f.readline().strip())
except Exception as e:
    print('Blocked:', e)
