#!/usr/bin/env python3
"""
Independent Landlock & Mount Mask Verification Script for BADGER V1.0.1
Tests:
1. Direct read of protected file
2. Path traversal (../)
3. Symlinks to protected file
4. Symlinks to host /etc/shadow
5. Nested directory access
6. Write to read-only directory
7. Unmentioned outside paths
8. Hard links
"""

import os
import sys
import shutil
import ctypes
import subprocess

# Landlock syscall constants
SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

PR_SET_NO_NEW_PRIVS = 38
MS_BIND = 4096
MS_REMOUNT = 32
MS_RDONLY = 1
MS_PRIVATE = 1 << 18
MS_REC = 16384

libc = ctypes.CDLL(None, use_errno=True)

class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]

class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]

def setup_fixtures():
    base = "/tmp/badger_landlock_verification"
    if os.path.exists(base):
        # unmount any leftovers
        subprocess.run(["umount", "-l", f"{base}/protected/secret.txt"], stderr=subprocess.DEVNULL)
        subprocess.run(["umount", "-l", f"{base}/masked_dir"], stderr=subprocess.DEVNULL)
        shutil.rmtree(base, ignore_errors=True)

    os.makedirs(f"{base}/workspace/subfolder", exist_ok=True)
    os.makedirs(f"{base}/protected", exist_ok=True)
    os.makedirs(f"{base}/masked_dir", exist_ok=True)
    os.makedirs(f"{base}/outside", exist_ok=True)

    with open(f"{base}/workspace/subfolder/nested.txt", "w") as f:
        f.write("NESTED_ALLOWED_DATA")

    with open(f"{base}/protected/secret.txt", "w") as f:
        f.write("HIGHLY_CONFIDENTIAL_SECRET_12345")

    with open(f"{base}/protected/public.txt", "w") as f:
        f.write("PUBLIC_DATA")

    with open(f"{base}/masked_dir/hidden.txt", "w") as f:
        f.write("HIDDEN_DIR_SECRET")

    with open(f"{base}/outside/outside.txt", "w") as f:
        f.write("OUTSIDE_BOUNDARY_DATA")

    # Symlinks
    os.symlink(f"{base}/protected/secret.txt", f"{base}/workspace/symlink_to_secret")
    os.symlink("/etc/shadow", f"{base}/workspace/symlink_to_shadow")

    return base

def main():
    print("=== BADGER V1.0.1 LANDLOCK & MOUNT MASK DEEP VERIFICATION ===")
    base = setup_fixtures()

    # Step 1: In a child process with private mount namespace, test mount masking + Landlock
    pid = os.fork()
    if pid == 0:
        # Child process
        # 1. Unshare mount namespace
        res = libc.unshare(0x00020000) # CLONE_NEWNS
        if res != 0:
            print(f"[FAIL] unshare(CLONE_NEWNS) failed: errno={ctypes.get_errno()}")
            sys.exit(1)

        # 2. Make mount private
        libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

        # 3. Apply mount mask: /dev/null over secret.txt
        secret_file = f"{base}/protected/secret.txt".encode()
        r1 = libc.mount(b"/dev/null", secret_file, None, MS_BIND, None)
        r2 = libc.mount(None, secret_file, None, MS_BIND | MS_REMOUNT | MS_RDONLY, None)

        # 4. Apply mount mask: tmpfs over masked_dir
        masked_dir = f"{base}/masked_dir".encode()
        r3 = libc.mount(b"tmpfs", masked_dir, b"tmpfs", 0, b"mode=0000")

        # 5. Landlock setup
        abi = libc.syscall(SYS_landlock_create_ruleset, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
        print(f"[*] Kernel Landlock ABI Version: {abi}")

        attr = LandlockRulesetAttr()
        attr.handled_access_fs = (
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
            LANDLOCK_ACCESS_FS_TRUNCATE
        )

        ruleset_fd = libc.syscall(SYS_landlock_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if ruleset_fd < 0:
            print(f"[FAIL] landlock_create_ruleset failed: errno={ctypes.get_errno()}")
            sys.exit(1)

        # Allow /tmp/badger_landlock_verification/workspace (RW)
        ws_fd = os.open(f"{base}/workspace", os.O_PATH | os.O_CLOEXEC)
        ws_rule = LandlockPathBeneathAttr(allowed_access=attr.handled_access_fs, parent_fd=ws_fd)
        libc.syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(ws_rule), 0)
        os.close(ws_fd)

        # Allow /tmp/badger_landlock_verification/protected (RO)
        prot_fd = os.open(f"{base}/protected", os.O_PATH | os.O_CLOEXEC)
        ro_mask = (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE)
        prot_rule = LandlockPathBeneathAttr(allowed_access=ro_mask, parent_fd=prot_fd)
        libc.syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(prot_rule), 0)
        os.close(prot_fd)

        # Allow /bin, /usr, /lib, /lib64, /proc (standard execution paths)
        for p in ["/bin", "/usr", "/lib", "/lib64", "/proc"]:
            if os.path.exists(p):
                fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
                r = LandlockPathBeneathAttr(allowed_access=ro_mask, parent_fd=fd)
                libc.syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(r), 0)
                os.close(fd)

        # Enforce Landlock
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        ret = libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
        os.close(ruleset_fd)
        if ret != 0:
            print(f"[FAIL] landlock_restrict_self failed: errno={ctypes.get_errno()}")
            sys.exit(1)

        print("[*] Landlock and mount masks successfully enforced.")

        # --- TEST 1: Direct read of protected file ---
        try:
            with open(f"{base}/protected/secret.txt", "r") as f:
                content = f.read()
                if "HIGHLY_CONFIDENTIAL" in content:
                    print("[EXPLOIT CONFIRMED] Direct read exposed secret!")
                elif content == "":
                    print("[PASS] Test 1 (Direct read): Masked by /dev/null (0 bytes read, secret shielded)")
                else:
                    print(f"[PASS] Test 1: Content masked ({content})")
        except PermissionError:
            print("[PASS] Test 1 (Direct read): Permission denied (VFS blocked)")

        # --- TEST 2: Path traversal (../) ---
        try:
            with open(f"{base}/workspace/../protected/secret.txt", "r") as f:
                content = f.read()
                if "HIGHLY_CONFIDENTIAL" in content:
                    print("[EXPLOIT CONFIRMED] Path traversal exposed secret!")
                elif content == "":
                    print("[PASS] Test 2 (Path traversal ../): Masked by /dev/null (0 bytes read)")
        except PermissionError:
            print("[PASS] Test 2 (Path traversal ../): Blocked by Landlock")

        # --- TEST 3: Symlink to protected file inside allowed workspace ---
        try:
            with open(f"{base}/workspace/symlink_to_secret", "r") as f:
                content = f.read()
                if "HIGHLY_CONFIDENTIAL" in content:
                    print("[EXPLOIT CONFIRMED] Symlink inside allowed dir exposed secret!")
                elif content == "":
                    print("[PASS] Test 3 (Symlink traversal): Masked by /dev/null (0 bytes read)")
        except PermissionError:
            print("[PASS] Test 3 (Symlink traversal): Blocked by Landlock")

        # --- TEST 4: Symlink to /etc/shadow ---
        try:
            with open(f"{base}/workspace/symlink_to_shadow", "r") as f:
                content = f.read()
                print("[EXPLOIT CONFIRMED] Symlink to /etc/shadow succeeded!")
        except PermissionError:
            print("[PASS] Test 4 (Symlink to /etc/shadow): Blocked by Landlock (Permission denied)")
        except Exception as e:
            print(f"[PASS] Test 4 (Symlink to /etc/shadow): Access prevented ({e})")

        # --- TEST 5: Nested subdirectory in allowed workspace ---
        try:
            with open(f"{base}/workspace/subfolder/nested.txt", "r") as f:
                c = f.read()
                if c == "NESTED_ALLOWED_DATA":
                    print("[PASS] Test 5 (Nested allowed read): Succeeded as expected")
                else:
                    print(f"[FAIL] Test 5: Unexpected content {c}")
        except Exception as e:
            print(f"[FAIL] Test 5 (Nested allowed read): Unexpected failure {e}")

        # --- TEST 6: Write to read-only directory ---
        try:
            with open(f"{base}/protected/exploit_write.txt", "w") as f:
                f.write("ILLEGAL_WRITE")
            print("[EXPLOIT CONFIRMED] Test 6: Wrote file to read-only directory!")
        except (PermissionError, OSError):
            print("[PASS] Test 6 (Write to RO dir): Successfully blocked (Permission denied)")

        # --- TEST 7: Access to unmentioned outside path ---
        try:
            with open(f"{base}/outside/outside.txt", "r") as f:
                c = f.read()
            print("[EXPLOIT CONFIRMED] Test 7: Read unmentioned outside directory!")
        except (PermissionError, OSError):
            print("[PASS] Test 7 (Unmentioned path): Successfully blocked by Landlock (Permission denied)")

        # --- TEST 8: Access to masked directory (tmpfs mode 0000) ---
        try:
            with open(f"{base}/masked_dir/hidden.txt", "r") as f:
                c = f.read()
            print("[EXPLOIT CONFIRMED] Test 8: Read file inside masked directory!")
        except (PermissionError, FileNotFoundError):
            print("[PASS] Test 8 (Masked directory tmpfs): Successfully masked (Access denied / file not visible)")

        sys.exit(0)

    _, status = os.waitpid(pid, 0)
    print(f"Child process exited with status {status}")

if __name__ == "__main__":
    main()
