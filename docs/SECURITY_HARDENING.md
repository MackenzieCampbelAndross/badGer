# BADGER Security Hardening & Kernel Guarantees

## 1. Operating System Hardening

To maintain the security guarantees of BADGER, host environments must satisfy:

1. **Kernel Version**: Linux 6.6+ with Landlock ABI v3 enabled.
2. **cgroups v2 Hierarchy**: Unified hierarchy mounted at `/sys/fs/cgroup`.
3. **No Unprivileged User Namespaces**: If unprivileged user namespaces are disabled on the host, the BADGER node agent runs with `CAP_SYS_ADMIN` and `CAP_BPF` to initialize sandboxes on behalf of workloads.
4. **Restricted BPF Access**: Host `kernel.unprivileged_bpf_disabled = 2` prevents unprivileged processes from loading eBPF programs or probing kernel memory.

---

## 2. Cryptographic Integrity Guarantees

1. **HMAC-SHA256 Policy Signatures**: Every policy is signed by the Control Plane authority. Tampered policies fail signature verification and are discarded.
2. **Cryptographic Audit Hash Chains**: Every audit event computes:
   $$\text{Hash}_n = \text{SHA256}(\text{Record}_n \parallel \text{Hash}_{n-1})$$
   Modifying any prior record invalidates all subsequent hash pointers in the chain.
3. **Zero Raw Secret Exposure**: Workload credentials (API tokens, passwords) are hashed via keyed HMAC-SHA256 upon observation. Raw secrets are never written to disk, logs, or control plane databases.
