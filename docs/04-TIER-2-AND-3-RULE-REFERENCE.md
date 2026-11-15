# Tier 2 and Tier 3 Rule Reference | v0.19

> **Purpose:** This document defines the purpose of every Tier 2 and Tier 3 audit rule in the Enterprise Linux Audit Policy. Tier 1 rules are defined by STIG/SRG requirements and are documented in the Implementation Guide.
>
> **As of:** 2026-11-14
> **Current release:** `enterprise-audit-policy-v0.19.zip`

---

## Table of Contents

- [Tier 2 — Core Security Monitoring](#tier-2---core-security-monitoring)
- [Tier 3 — Threat Specific](#tier-3---threat-specific)
- [Appendix A: Applicability Matrix](#appendix-a-applicability-matrix)
- [Appendix B: Audit Key Reference](#appendix-b-audit-key-reference)

---

## Tier 2 — Core Security Monitoring

All Tier 2 rules are in `tier-2-core-security/`. Every file exists in all 4 environments (on-prem, AWS, Azure, GCP) and both architectures (x86_64, ARM64).

### 20-security-process.rules

**Purpose:** Monitor privileged API calls (setuid/setresuid) by non-root users for potential privilege escalation.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -F auid>=1000 -F auid!=unset -k t2_privilege_api` | Track setuid/setresuid calls by real users (auid>=1000) for privilege escalation detection |
| `-a always,exit -F arch=b32 -S setuid,setreuid,setresuid -F auid>=1000 -F auid!=unset -k t2_privilege_api` | Same as above for 32-bit compatibility ABI |

**Commented candidates:**
- `/usr/bin/systemctl` service admin execution
- `/usr/sbin/auditctl` audit admin execution
- `/usr/bin/rpm` package admin execution

---

### 21-security-persistence.rules

**Purpose:** Monitor systemd service file modifications for persistence mechanism detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -F dir=/etc/systemd/system -F perm=wa -k t2_persistence` | Track writes to systemd system unit directory for persistence detection |

**Commented candidates:**
- `/etc/cron.d` cron job persistence
- `/var/spool/cron` user crontab persistence
- `/etc/ld.so.conf.d` library configuration persistence

---

### 22-security-credential.rules

**Purpose:** Monitor authentication configuration and SSH configuration changes for credential tampering detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -F dir=/etc/pam.d -F perm=wa -k t2_auth_change` | Track PAM configuration modifications for credential tampering detection |
| `-a always,exit -F arch=b64 -F dir=/etc/ssh -F perm=wa -k t2_ssh_change` | Track SSH configuration modifications for credential tampering detection (x64) |
| `-a always,exit -F arch=b32 -F dir=/etc/ssh -F perm=wa -k t2_ssh_change` | Track SSH configuration modifications for credential tampering detection (b32) |

**Commented candidates:**
- `/etc/security` security limits configuration

---

### 23-security-network.rules

**Purpose:** Monitor network configuration changes for unauthorized network modification detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S sethostname,setdomainname -F auid>=1000 -F auid!=unset -k t2_net_config` | Track hostname/domainname changes by real users |
| `-a always,exit -F arch=b64 -F path=/etc/hosts -F perm=wa -k t2_net_config` | Track /etc/hosts modifications for DNS spoofing detection (x64) |
| `-a always,exit -F arch=b32 -S sethostname,setdomainname -F auid>=1000 -F auid!=unset -k t2_net_config` | Track hostname/domainname changes by real users (b32) |

**Commented candidates:**
- `/etc/resolv.conf` DNS resolver configuration

---

### 24-enhanced-process.rules

**Purpose:** Monitor process execution by root and non-root users for command execution detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k t2_exec_user` | Track non-root process execution (x64) |
| `-a always,exit -F arch=b64 -S execve -F auid=0 -k t2_exec_root` | Track root process execution (x64) |
| `-a always,exit -F arch=b64 -S execveat -F auid>=1000 -F auid!=unset -k t2_exec_user` | Track non-root process execution via execveat (x64) |
| `-a always,exit -F arch=b64 -S execveat -F auid=0 -k t2_exec_root` | Track root process execution via execveat (x64) |
| `-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k t2_exec_user` | Track non-root process execution (b32) |
| `-a always,exit -F arch=b32 -S execveat -F auid>=1000 -F auid!=unset -k t2_exec_user` | Track non-root process execution via execveat (b32) |
| `-a always,exit -F arch=b32 -S execve -F auid=0 -k t2_exec_root` | Track root process execution (b32) |
| `-a always,exit -F arch=b32 -S execveat -F auid=0 -k t2_exec_root` | Track root process execution via execveat (b32) |

---

### 25-enhanced-filesystem.rules

**Purpose:** Monitor root-initiated file modification and deletion for data tampering detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid=0 -k t2_root_filechange` | Track root permission changes (x64) |
| `-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid=0 -k t2_root_filechange` | Track root ownership changes (x64) |
| `-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid=0 -k t2_root_filedelete` | Track root file deletion/renaming (x64) |
| `-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid=0 -k t2_root_filechange` | Track root permission changes (b32) |
| `-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid=0 -k t2_root_filechange` | Track root ownership changes (b32) |
| `-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid=0 -k t2_root_filedelete` | Track root file deletion/renaming (b32) |

---

### 26-enhanced-network.rules

**Purpose:** Monitor outbound network connections by real users for data exfiltration detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S connect -F auid>=1000 -F auid!=unset -k t2_user_connect` | Track outbound network connections by real users (x64) |
| `-a always,exit -F arch=b32 -S connect -F auid>=1000 -F auid!=unset -k t2_user_connect` | Track outbound network connections by real users (b32) |

---

### 27-cloud-host-security.rules

**Purpose:** Cloud-hosted environment security monitoring. **Active rules are environment-specific** and populated at deployment time. This file documents the cloud-hosted extension to the baseline policy.

| Rule | Purpose |
|---|---|
| *(none — environment-specific rules added at deployment)* | Cloud-hosted security monitoring (AWS SSM, Azure Linux Agent, GCP Guest Agent) |

**Note:** This file exists in all profiles for documentation purposes. On-prem profiles include it to document the gap between on-prem and cloud-hosted monitoring.

---

### 28-security-package-policy.rules

**Purpose:** Monitor package repository configuration changes for supply chain attack detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -F dir=/etc/yum.repos.d -F perm=wa -k t2_pkg_repo` | Track package repository configuration changes for supply chain detection (x64) |

**Commented candidates:**
- `/etc/dnf/dnf.conf` DNF configuration

**Applicability:** Active on RHEL-family/Amazon Linux profiles. The DNF candidate is commented because DNF is not installed by default on all images.

---

### 29-system-config-integrity.rules

**Purpose:** Monitor system configuration file integrity for unauthorized modification detection. Includes broad `/etc` directory monitoring (v0.19) and targeted shell startup initialization watches (v0.17).

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -F dir=/etc -F perm=wa -k t2_etc_integrity` | Track all writes to /etc directory for integrity monitoring (x64) |
| `-a always,exit -F arch=b32 -F dir=/etc -F perm=wa -k t2_etc_integrity` | Track all writes to /etc directory for integrity monitoring (b32) |
| `-a always,exit -F arch=b64 -F path=/etc/profile -F perm=wa -k t2_shell_init` | Track /etc/profile modifications for shell initialization tampering (x64) |
| `-a always,exit -F arch=b32 -F path=/etc/profile -F perm=wa -k t2_shell_init` | Track /etc/profile modifications for shell initialization tampering (b32) |
| `-a always,exit -F arch=b64 -F path=<bashrc> -F perm=wa -k t2_shell_init` | Track Bash RC modifications for shell initialization tampering (x64) |
| `-a always,exit -F arch=b32 -F path=<bashrc> -F perm=wa -k t2_shell_init` | Track Bash RC modifications for shell initialization tampering (b32) |
| `-a always,exit -F arch=b64 -F dir=/etc/profile.d -F perm=wa -k t2_shell_init` | Track /etc/profile.d modifications for shell initialization tampering (x64) |
| `-a always,exit -F arch=b32 -F dir=/etc/profile.d -F perm=wa -k t2_shell_init` | Track /etc/profile.d modifications for shell initialization tampering (b32) |

**Path notes:**
- RHEL-family/Amazon Linux: `<bashrc>` = `/etc/bashrc`
- Ubuntu/SLES/Debian: `<bashrc>` = `/etc/bash.bashrc`
- ARM64: Only b64 rules (no b32 compatibility ABI)

**Commented candidates:**
- `/proc/sysrq-trigger` Magic SysRq trigger (kernel-specific, requires acceptance testing)
- `/proc/sys/kernel/sysrq` Magic SysRq sysctl configuration (kernel-specific)

---

## Tier 3 — Threat Specific

All Tier 3 rules are in `tier-3-threat-specific/`. Every file exists in all 4 environments (on-prem, AWS, Azure, GCP) and both architectures (x86_64, ARM64). Tier 3 is **selective** — only deploy when applicable.

### 30-exploitation.rules

**Purpose:** Monitor exploitation techniques including process injection, container escape, and memory manipulation.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S ptrace -F auid>=1000 -F auid!=unset -k t3_ptrace` | Track ptrace calls for process injection detection (x64) |
| `-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=unset -k t3_bpf` | Track BPF calls for eBPF-based exploitation detection (x64) |
| `-a always,exit -F arch=b64 -S unshare,setns -F auid>=1000 -F auid!=unset -k t3_namespace` | Track namespace manipulation for container escape detection (x64) |
| `-a always,exit -F arch=b64 -S memfd_create -F auid>=1000 -F auid!=unset -k t3_memfd` | Track memfd_create for in-memory payload execution detection (x64) |
| `-a always,exit -F arch=b32 -S ptrace -F auid>=1000 -F auid!=unset -k t3_ptrace` | Track ptrace calls for process injection detection (b32) |
| `-a always,exit -F arch=b32 -S bpf -F auid>=1000 -F auid!=unset -k t3_bpf` | Track BPF calls for eBPF-based exploitation detection (b32) |
| `-a always,exit -F arch=b32 -S unshare,setns -F auid>=1000 -F auid!=unset -k t3_namespace` | Track namespace manipulation for container escape detection (b32) |
| `-a always,exit -F arch=b32 -S memfd_create -F auid>=1000 -F auid!=unset -k t3_memfd` | Track memfd_create for in-memory payload execution detection (b32) |

---

### CVE-2026-31431.rules (Copy Fail — AF_ALG)

**Purpose:** Monitor AF_ALG socket creation with splice for Copy Fail exploitation.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg` | Track AF_ALG socket creation (x64) |
| `-a always,exit -F arch=b64 -S splice -F auid>=1000 -F auid!=unset -k splice_user` | Track splice syscall by real users for data transfer correlation (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (x64) |
| `-a always,exit -F arch=b32 -S socket -F a0=38 -k af_alg` | Track AF_ALG socket creation (b32) |
| `-a always,exit -F arch=b32 -S splice -F auid>=1000 -F auid!=unset -k splice_user` | Track splice syscall by real users for data transfer correlation (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (b32) |

---

### CVE-2026-43284.rules (Dirty Frag)

**Purpose:** Monitor splice/vmsplice for Dirty Frag exploitation.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S splice,vmsplice -F success=1 -F auid>=1000 -F auid!=unset -k splice_user` | Track successful splice/vmsplice by real users (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (x64) |
| `-a always,exit -F arch=b32 -S splice,vmsplice -F success=1 -F auid>=1000 -F auid!=unset -k splice_user` | Track successful splice/vmsplice by real users (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (b32) |

---

### CVE-2026-43500.rules (Dirty Frag — equivalent)

**Purpose:** Monitor splice/vmsplice for Dirty Frag equivalent sensor requirement.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S splice,vmsplice -F success=1 -F auid>=1000 -F auid!=unset -k splice_user` | Track successful splice/vmsplice by real users (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (x64) |
| `-a always,exit -F arch=b32 -S splice,vmsplice -F success=1 -F auid>=1000 -F auid!=unset -k splice_user` | Track successful splice/vmsplice by real users (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k process_creation` | Track process creation for execution correlation (b32) |

---

### CVE-2026-74580.rules (Failed raw-socket activity)

**Purpose:** Monitor failed raw socket creation for exploitation detection.

| Rule | Purpose |
|---|---|
| `-a always,exit -F arch=b64 -S socket -F a1=3 -F success=0 -F auid>=1000 -F auid!=unset -k sock_raw_eafnosupport` | Track failed raw socket creation by real users (x64) |
| `-a always,exit -F arch=b32 -S socket -F a1=3 -F success=0 -F auid>=1000 -F auid!=unset -k sock_raw_eafnosupport` | Track failed raw socket creation by real users (b32) |

---

### CVE-2026-109618.rules (PHP2Shell — httpd/nginx/java)

**Status:** **Commented out** — all rules are candidates pending workload verification.

**Purpose:** Monitor PHP-to-shell execution via web service executables.

| Rule | Status | Purpose |
|---|---|---|
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/httpd -k php2shell_service_exec` | Commented | Track httpd process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/nginx -k php2shell_service_exec` | Commented | Track nginx process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/java -k php2shell_service_exec` | Commented | Track java process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/sbin/httpd -k php2shell_service_exec` | Commented | Track httpd process creation for PHP2Shell correlation (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/sbin/nginx -k php2shell_service_exec` | Commented | Track nginx process creation for PHP2Shell correlation (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/bin/java -k php2shell_service_exec` | Commented | Track java process creation for PHP2Shell correlation (b32) |

---

### CVE-2026-109619.rules (PHP2Shell — equivalent)

**Status:** **Commented out** — all rules are candidates pending workload verification.

**Purpose:** Monitor PHP-to-shell execution via web service executables (equivalent sensor).

| Rule | Status | Purpose |
|---|---|---|
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/httpd -k php2shell_service_exec` | Commented | Track httpd process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/nginx -k php2shell_service_exec` | Commented | Track nginx process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/java -k php2shell_service_exec` | Commented | Track java process creation for PHP2Shell correlation (x64) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/sbin/httpd -k php2shell_service_exec` | Commented | Track httpd process creation for PHP2Shell correlation (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/sbin/nginx -k php2shell_service_exec` | Commented | Track nginx process creation for PHP2Shell correlation (b32) |
| `-a always,exit -F arch=b32 -S execve,execveat -F exe=/usr/bin/java -k php2shell_service_exec` | Commented | Track java process creation for PHP2Shell correlation (b32) |

---

## Appendix A: Applicability Matrix

### Tier 2 File Applicability

| File | All Environments | x86_64 | ARM64 | Notes |
|---|---|---|---|---|
| 20-security-process.rules | Yes | Yes | Yes | |
| 21-security-persistence.rules | Yes | Yes | Yes | |
| 22-security-credential.rules | Yes | Yes | Yes | |
| 23-security-network.rules | Yes | Yes | Yes | |
| 24-enhanced-process.rules | Yes | Yes | Yes | |
| 25-enhanced-filesystem.rules | Yes | Yes | Yes | |
| 26-enhanced-network.rules | Yes | Yes | Yes | |
| 27-cloud-host-security.rules | Yes | Yes | Yes | 0 active rules; environment-specific at deployment |
| 28-security-package-policy.rules | Yes | Yes | Yes | yum.repos.d watch; DNF candidate commented |
| 29-system-config-integrity.rules | Yes | Yes (b64+b32) | Yes (b64 only) | OS-specific bashrc path; Debian profile.d commented |

### Tier 3 File Applicability

| File | All Environments | Active | Commented | Notes |
|---|---|---|---|---|
| 30-exploitation.rules | Yes | 8 | 0 | Selective deployment |
| CVE-2026-31431.rules | Yes | 6 | 0 | Copy Fail detection |
| CVE-2026-43284.rules | Yes | 4 | 0 | Dirty Frag detection |
| CVE-2026-43500.rules | Yes | 4 | 0 | Dirty Frag equivalent |
| CVE-2026-74580.rules | Yes | 2 | 0 | Raw socket failure detection |
| CVE-2026-109618.rules | Yes | 0 | 6 | PHP2Shell (commented) |
| CVE-2026-109619.rules | Yes | 0 | 6 | PHP2Shell equivalent (commented) |

### Architecture Notes

- **x86_64:** Uses both b64 and b32 rules where applicable for 32-bit compatibility ABI coverage.
- **ARM64:** Uses only b64 rules. ARM64 has no b32 compatibility ABI; `*at` variants are native (no separate b32 names needed).

---

## Appendix B: Audit Key Reference

| Key | Tier | Purpose |
|---|---|---|
| `t2_privilege_api` | Tier 2 | Privilege escalation via setuid/setresuid |
| `t2_persistence` | Tier 2 | Persistence mechanism detection |
| `t2_auth_change` | Tier 2 | Authentication configuration modification |
| `t2_ssh_change` | Tier 2 | SSH configuration modification |
| `t2_net_config` | Tier 2 | Network configuration modification |
| `t2_exec_user` | Tier 2 | Non-root process execution |
| `t2_exec_root` | Tier 2 | Root process execution |
| `t2_root_filechange` | Tier 2 | Root file permission/ownership changes |
| `t2_root_filedelete` | Tier 2 | Root file deletion/renaming |
| `t2_user_connect` | Tier 2 | Outbound network connections by real users |
| `t2_pkg_repo` | Tier 2 | Package repository configuration changes |
| `t2_etc_integrity` | Tier 2 | All /etc directory writes (broad integrity) |
| `t2_shell_init` | Tier 2 | Shell initialization file modification |
| `t3_ptrace` | Tier 3 | Process injection via ptrace |
| `t3_bpf` | Tier 3 | eBPF-based exploitation |
| `t3_namespace` | Tier 3 | Container escape via namespace manipulation |
| `t3_memfd` | Tier 3 | In-memory payload execution via memfd |
| `af_alg` | Tier 3 | AF_ALG socket creation (CVE-2026-31431) |
| `splice_user` | Tier 3 | Splice/vmsplice by real users (CVE-2026-31431/43284/43500) |
| `process_creation` | Tier 3 | Process creation for execution correlation |
| `sock_raw_eafnosupport` | Tier 3 | Failed raw socket creation (CVE-2026-74580) |
| `php2shell_service_exec` | Tier 3 | PHP-to-shell via service executables (CVE-2026-109618/109619) |
| `t2_sysrq` | Tier 2 (candidate) | Magic SysRq trigger (commented) |
