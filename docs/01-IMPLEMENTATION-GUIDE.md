# 01 — Implementation Guide | v0.19

## v0.17 — Targeted mandatory Tier 2 shell-startup monitoring

`29-system-config-integrity.rules` now includes **active** watch rules for `/etc/profile` and the OS-family Bash startup configuration (`/etc/bashrc` on RPM-family/Amazon, `/etc/bash.bashrc` on Ubuntu/Debian/SLES). On non-Debian profiles it also monitors `/etc/profile.d` (including new files within the watched subtree). These watch `wa` access, not reads or command contents. Both b64 and b32 are present on x86_64; ARM64 has b64 only.

**Deployment preflight:** Confirm that active paths exist as the expected file or directory on the selected OS/image before deploying. Package-file lists establish normal installed paths, not runtime guarantees. Debian does **not** have an automatically enabled `/etc/profile.d` watch; uncomment it only if the directory exists *and* `/etc/profile` sources it. If any applicable mandatory path is absent, remediate image prerequisites or obtain the correct applicability/exception decision; never silently disregard the rule.

**Current v0.19 boundary:** Active `/etc` directory auditing is present for file creation and modification. For host creation detection, rely on the approved native auditd parent-directory rule, assess filesystem/mount limitations, and use the waiver process if the required rule cannot be supported. SSH/sudoers watches may already exist in Tier 1; keep that provenance and only enable missing package-dependent watches when their paths exist. SysRq and user-home startup hunting remain separate/conditional. No host evidence exists for this release.


## v0.16.4 — Ubuntu 22.04 STIG coverage boundary

**Ubuntu 22.04 V2R10 (v0.16.4 offline mapping):** All **49 published audit-rule-related V-IDs** are represented by active Tier 1/Finalize directives in all eight Ubuntu 22.04 variants, including the AppArmor parser, cron watches, useradd and immutability. This is a source-to-rule presence/intent cross-check, **not** official DISA ZIP hash verification, host-load evidence, or overall STIG compliance. Mandatory watches with missing-file/package prerequisites still require remediation or an approved exception. See the full 49-row traceability table in Document 03.

## Scope and deployment decision

This package provides Linux Audit engineering candidates for **full OS hosts and VMs**, on-premises and in AWS, Azure, and GCP. It is not an auditd configuration for container-only workloads or a substitute for hypervisor/cloud audit services. Select by **actual host OS/version, hosting environment, and CPU architecture**. It does not automatically satisfy STIG configuration requirements outside audit rules.

Mandatory **Tier 1 Baseline + Tier 2 SOC/IR**; Tier 3 only when threat-directed. The finalizer (`-e 2`) is deployed *last* after validation. Obtain authorization for `-D`, `-f 2`, and `-e 2` impacts.

### 1. Select the correct directory

```bash
cat /etc/os-release
uname -m
sudo auditctl -s
```

| Host | Selected profile path (within the extracted package) |
|---|---|
| RHEL 9 x86_64 on-prem | `rules/on-prem/rhel9/` |
| RHEL 9 ARM64 on-prem | `rules/on-prem/rhel9/aarch64/` |
| Ubuntu 24.04 x86_64 on AWS | `rules/aws/ubuntu2404/` |
| Ubuntu 24.04 ARM64 on AWS | `rules/aws/ubuntu2404/aarch64/` |
| Amazon Linux 2023 ARM64 | `rules/aws/amazon-linux-2023/aarch64/` |
| Ubuntu 26.04 x86_64 on GCP | `rules/gcp/ubuntu2604/` |

**Never recursively copy the OS directory:** its nested `aarch64/` holds a *different, mutually exclusive* complete ruleset. For x86_64 use the profile root's immediate tier directories; for ARM64 use its `aarch64/` tier directories.

On x86_64, `arch=b64` and `arch=b32` denote separate syscall tables; b32 monitoring is included even though many images do not ship 32-bit userspace. On ARM64 only native `arch=b64` rules are installed. The ARM64 translations replace legacy syscalls absent on that ABI (for example `unlink` → `unlinkat`, `rename` → `renameat`/`renameat2`, `creat` → `openat`/`openat2`). **These mappings must be tested on the target kernel**: architecture translation is not automatically equivalent to the current OS product STIG.


### Offline, package-manifest-first path verification (v0.14)

Use a per-image assumption ledger when actual hosts are unavailable. First, confirm the exact OS/version/architecture and target image family. Next, compare each active file/directory/executable path with the **OS release's published package file lists** and cloud agent documentation. Record separately: (a) vendor-documented package location, (b) whether the package is part of the **published base image**, (c) whether the watched object is created only at boot or after configuration, (d) whether the path is a symlink/`usr-merge` alias, and (e) whether the rule will reject a missing path. A valid pathname alone is not proof of installed-file existence.

| Path or behavior | Offline conclusion and required action |
|---|---|
| Ubuntu 22.04/24.04 AppArmor parser | `apparmor` manifest ships `/sbin/apparmor_parser`; do not apply 26.04 pathname to these STIG-derived rules |
| Ubuntu 26.04 AppArmor parser | `apparmor` manifest ships `/usr/sbin/apparmor_parser` (amd64/arm64); this release corrected the active rule |
| Ubuntu 24.04 PAM helpers | `libpam-modules-bin` manifest lists `/usr/sbin/{pam_timestamp_check,unix_update,unix_chkpwd}`; preserve STIG `/sbin/unix_update` only when the alias resolves to the actual inode |
| Ubuntu 24.04 `/usr/bin/chacl` | Shipped by the optional `acl` package; absence needs package remediation or applicability decision, not a silent deletion |
| Ubuntu 24.04 `/var/log/sudo.log` | Not a default sudo file log. STIG-derived watch retained; configure/create the log as approved before applying it, or document the approved exception. Missing file can reject the rule |
| `/etc/security/opasswd`, `/var/log/faillog`, login history files | Generated/legacy/conditional; published package paths alone do not establish existence |
| Debian 12 vs 13 PAM | `libpam-modules-bin` file lists differ (`/sbin` vs `/usr/sbin` helpers); review legacy aliases on Debian 12 and new paths on 13 |
| AWS SSM on Ubuntu | Snap may package under `/snap/amazon-ssm-agent/current`, with writable overrides under `/etc/amazon/ssm`; 26.04 defaults not established by cited Snap guide |
| Azure | `/etc/waagent.conf` is documented; whether the guest agent or cloud-init owns provisioning is image-specific |
| GCP | `/etc/default/instance_configs.cfg.template` overrides `.distro` and base `.cfg`; `/var/lib/google-guest-agent` holds plugin state for modern versions, and may be absent |


### Published base-image package manifests (no VM boot needed)

Official generic Ubuntu cloud-image manifests for Jammy 22.04, Noble 24.04 and Resolute 26.04 provide exact *package names* installed on a particular image build. This is stronger evidence than a distribution's package catalog, but a vendor-customized EC2/Azure/GCP image may differ. The referenced **generic Ubuntu 24.04 and 26.04 amd64 cloud images list `apparmor` and `libpam-modules-bin`, but not `auditd` or `acl`**. The package manager may support `auditd` without that package being preinstalled. If `acl` is absent, a STIG-derived `chacl` watch will not load; install the package or record the approved applicability exception. The `apparmor` package location can be valid without the audit subsystem being installed.

- Ubuntu 22.04 generic amd64 image: https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.manifest
- Ubuntu 24.04 generic amd64 image: https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.manifest
- Ubuntu 26.04 generic amd64 and arm64 images: https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.manifest and https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-arm64.manifest
- Amazon Linux 2023 standard/minimal/container comparison: https://docs.aws.amazon.com/linux/al2023/ug/image-comparison.html
- Amazon Linux 2027 preview standard/minimal/container comparison: https://docs.aws.amazon.com/linux/al2027/ug/AMI-minimal-and-standard-differences.html

AWS documents SSM Agent in the **standard** Amazon Linux 2023 and 2027 AMIs, **not** the minimal AMIs; `awscli-2` appears in both standard and minimal image tables, and the `audit` package is listed for those image types. Therefore *Amazon Linux version alone is insufficient to decide SSM applicability*: record whether the image is standard or minimal. AL2027 is preview-only. For Ubuntu AWS images, do not equate the generic Canonical image manifest to an EC2-specific pre-installed Snap package set.

This image-manifest evidence is suitable for an offline build prerequisite checklist. It cannot prove `/var/log/sudo.log` or `/etc/security/opasswd` exists, because such files are runtime/configuration-created and may not appear in package manifests.

**Release block:** If a mandatory audit watch targets an absent object, the profile is not a safe universal drop-in. An offline verifier cannot waive the rule on a customer's behalf. Require the image builder to create/install the prerequisite or obtain an approved applicability/waiver decision. Never call an unverified profile 'deployable' simply because it parses correctly.

### 2. Perform a path and applicability preflight

The selected directory must contain **25 `.rules` files**, distributed across the 4 tier folders. Before copying rules, check every active `-w`, `-F path=`, and `-F dir=` target against the actual host. The following is a read-only command run from the extracted package directory:

```bash
# Edit to match the exact host. For ARM64 append /aarch64 to the value.
PROFILE="$PWD/rules/aws/ubuntu2404"

awk '
  /^-w / { print $2 }
  /^-a / {
    for (i=1; i<=NF; i++)
      if ($i == "-F" && $(i+1) ~ /^(path|dir)=/) {
        split($(i+1), part, "="); print part[2]
      }
  }
' "$PROFILE"/tier-1-baseline/*.rules "$PROFILE"/tier-2-core-security/*.rules \
  | sort -u | while IFS= read -r target; do
      test -e "$target" || printf 'MISSING: %s\n' "$target"
    done
```

Resolve all `MISSING` paths: verify the exact package/service prerequisite and correct vendor path; install required components if applicable; or obtain documented **N/A or approved waiver** when not applicable. Never silently remove a mandatory rule. This is especially important for STIG execution watches and login files on Ubuntu 24.04, RHEL 9 privileged utilities, optional SELinux/AppArmor executables, and minimal cloud images. Also inspect `auditctl -l` for any preexisting `-a never,task` rule.

**MAC enforcement is separate:** run `getenforce`/`sestatus` where SELinux is installed, or `aa-status` where AppArmor is installed. Native SELinux AVC and AppArmor denial records must reach audit/journald and Splunk; watching policy edits does not capture or enable every denial.

### 3. Stage mandatory tiers (do not install finalization during tests)

Use a disposable VM/cloud instance for first testing. This procedure must be reviewed for the host's existing audit rules because **`00-audit-foundation.rules` includes `-D`**. Do not delete unrelated pre-existing audit rules without an approved change.

```bash
# Example: local staging, after resolving preflight failures.
PROFILE="$PWD/rules/aws/ubuntu2404"

sudo mkdir -p /etc/audit/rules.d
# Back up the existing audit configuration in the approved change procedure.
# Then COPY ONLY THE RULES FROM THE SELECTED PROFILE/TIERS (not recursively).
sudo install -m 0640 "$PROFILE"/tier-1-baseline/*.rules /etc/audit/rules.d/
sudo install -m 0640 "$PROFILE"/tier-2-core-security/*.rules /etc/audit/rules.d/
# Do not copy 99-finalize.rules at this point.
sudo augenrules --check
sudo augenrules --load
sudo auditctl -s
sudo auditctl -l
```

Staging is safe only if there is no preexisting `-e 2` immutable rule and the host/auditing authority approved the test. Confirm that *every intended active rule* was loaded; `augenrules --load` returning zero is insufficient evidence. Preserve terminal/kernel journal output and account for any missing watches. `-f 2` can cause a kernel panic on serious audit failure; test failure/backlog behavior in a disposable environment first. Some deployments require an authorized reboot before a changed configuration can take effect.

**Tier 3:** install only a threat-directed file with a designated owner and review date. **Finalize:** after full approval, install `finalize/99-finalize.rules`, re-check/load, and document that audit rules become immutable until reboot:

```bash
sudo install -m 0640 "$PROFILE"/finalize/99-finalize.rules /etc/audit/rules.d/
sudo augenrules --check
sudo augenrules --load
sudo auditctl -s
```

Do not apply a new profile's rules on top of a prior profile, or mix x86_64 and ARM64 files. The package deliberately does not include a deployment tool or modify host files automatically.

### 4. Validate event generation and Splunk ingestion

Generate authorized, non-destructive test events and verify corresponding audit keys/records with `ausearch -k <key> -i` or SIEM queries. At minimum test: account metadata change, sudo/privileged exec, `execve` **and `execveat`**, failed file access (`EACCES` and `EPERM`), file rename/delete, service persistence, package repo config, MAC policy administration, and (in cloud) noninteractive daemon execution/configuration change. A rule matching on a console may still fail to forward or extract relevant metadata in Splunk.

Capture before/after `auditctl -s`: `lost`, `backlog`, `backlog_limit`, and `enabled`. Validate identity correlation (`auid`, UID/EUID), `exe`, process ID, command arguments, file PATH records, event time, and source host in SIEM. Match event retention and collection routing to your enterprise policy.

**Performance gate:** lab → canary → peak load → broader deployment; compare audit loss (must not increase), sustained backlog, EPS/GB/day, CPU/system CPU, disk I/O, application SLOs, and SIEM license/retention. Mandatory Tier 2 includes broad `execve`, `execveat`, root-file-mutation and network `connect` rules. New cloud daemon rules add background execution and connection telemetry. If the workload cannot sustain a required capability, optimize without losing it or obtain an authorized waiver; do not mark it compliant.

### 5. Cloud host auditing vs cloud control-plane logs

`27-cloud-host-security.rules` activates **noninteractive root daemon** `execve`/`execveat`, `connect` and `/etc` write/attribute monitoring on the selected provider. Those events help attribute guest-management execution; they do **not** identify the AWS/Azure/GCP API call or console principal when a remote actor changes a security group, NSG, IAM policy, or firewall.

The same file includes **commented conditional provider watches**. Each image must inventory installed guest agents, CLI tools, credential/configuration directories, and enable the correct exact-path watches after the preflight. If the agent exists and the requirement applies, leaving the watch commented requires remediation or a waiver. Missing/optional agent paths are not automatically activated because `auditctl` can reject watches against missing targets.

| Provider | Verify the guest paths/components | Mandatory companion telemetry (outside auditd) |
|---|---|---|
| **AWS** | SSM Agent (`/var/lib/amazon/ssm`, `/etc/amazon/ssm`), cloud-init, AWS CLI, local AWS credential files where present | **CloudTrail** management events for EC2 security groups, IAM/STS, API calls; VPC Flow Logs and AWS Config as required |
| **Azure** | Azure Linux Agent (`/etc/waagent.conf`, `/var/lib/waagent`), cloud-init, Azure CLI and credential paths | **Azure Activity Log** for resource-manager NSG/RBAC changes; relevant identity/data/resource logs; VNet Flow Logs as applicable |
| **GCP** | Guest agent (`/etc/default/instance_configs.cfg` and variants), cloud-init, Google Cloud CLI and local credentials | **Cloud Audit Logs** (Admin Activity and relevant Data Access/Policy Denied), firewall/IAM management; VPC Flow Logs as applicable |

Ensure management events are actually enabled/collected at the required AWS account / Azure subscription / GCP project or organization scope, forwarded to SIEM, and searchable. A single guest process executing a CLI is *not* evidence that all API calls are observed by host auditd; SDK requests and control-plane calls from elsewhere are invisible to guest auditd.

### 6. Special product status

- **Ubuntu 24.04:** x86_64 Tier 1 retains 64/64 exact audit directive lines in the user-provided **V1R7 extraction** (49 rule-bearing V-IDs including `-e 2`). This is only source-line matching, **not** independent official archive verification or host STIG compliance. ARM64 translation needs its own compliance applicability review.
- **RHEL 9:** x86_64 Tier 1 includes 81/81 directives from the **prior locally assembled RHEL9 V2R10 reference package**. Each source line has a reference marker. Obtain the **current** official DISA source and independently verify V-IDs, N/A conditions, paths, and behavior. ARM64 translation is not certified by the old reference.
- **Other OS versions:** not yet mapped to their current, respective product-specific STIG/SRG. Shared enterprise coverage rules are intentionally **not** evidence of equivalent compliance. Do not transfer another product's STIG V-ID to them.
- **Ubuntu 26.04:** AppArmor 5.x and cloud agents require live validation. No current Ubuntu 26.04 product STIG has been independently verified here; apply the authorized SRG/organizational baseline until one is available.
- **Amazon Linux 2027:** treat as preview-only; no production approval or STIG claim.

### 7. Release evidence for each deployment

Record OS release, architecture, provider/account/project, image ID/kernel/audit version, applicable STIG release, enabled modules/agents, preflight path results, rule-load output, executed test cases, Splunk events/field extraction, audit loss/backlog/EPS, peak performance, cloud-native feed coverage, applicable N/A/waiver ticket, approval, and expiry/retest date. Only promote an individual **OS + cloud + architecture + tested image/kernel** after all gates pass.

## v0.14 — Deployment and applicability: Ubuntu and Debian gaps

**N1 (Ubuntu 22.04 V2R10; historical v0.14 assessment, superseded by the v0.16.4 published-source mapping above):** The former sparse profile was replaced with a broader Tier 1 candidate reflecting the Ubuntu 24.04 audit objectives but with Ubuntu 22.04 specific AppArmor parser activation (`/sbin/apparmor_parser`, V-260604). V2R10 immutability (V-288816) remains in Finalize. Obtain and preserve the original official V2R10 archive SHA256 (review references `2229b5be…` but that archive was not included in this task), extract the full audit rule-bearing V-IDs, compare all check/fix requirements, and document remaining differences. **Do not state full 49/49 verified STIG coverage.**

**N2 (Ubuntu 26.04):** The Tier 1 directives now match the Ubuntu 24.04 *engineering objectives* except for release-specific AppArmor handling and documented prerequisite assumptions. They must **not** be labeled an Ubuntu 26.04 DISA STIG baseline. Assess the exact current vendor package/image manifests and do not silently ignore missing watches.

**N3 (Debian 12/13 and Proxmox):** Added explicit user/privileged-command monitoring, login-record watches, and file-access objectives using Debian-specific path assumptions. Commands from packages not universally present (`sudo`, `acl`, PAM helpers, `openssh-client`, `cron`, AppArmor) remain commented as **conditional** requirements pending package installation or verified applicability, not automatically N/A. For Proxmox, `/etc/pve` is a `pmxcfs` FUSE filesystem; do not presume that ordinary auditd watch semantics cover its clustered configuration. Pair host audit with supported Proxmox task/API/cluster log sources.

**Acceptance rule:** These changes improve *engineering coverage* and remove the misleading parity assumption; they do not substitute for source V-ID reconciliation, image-path checks, kernel loading, event evidence or the organizational waiver process.

## v0.15 — Debian 12/13 and Proxmox preflight (without host event collection)

The Debian Tier 1 audit objective is mandatory, but no **unconditional** file watch can be promised to load against every Debian/Proxmox image. In particular, do not copy Ubuntu `-w /var/log/journal`, `/var/log/sudo.log`, legacy lastlog/faillog, `cron`, `sudo`, `acl`, or AppArmor paths without their installed-file prerequisites. Auditd may reject a watch if its target does not exist. An uncommented watch is not an installation step.

For a managed Debian or PVE image, verify package ownership and default paths against Debian 12 (Bookworm) / Debian 13 (Trixie) package inventories before enabling conditional rules. Typical validation commands **on a representative image or image filesystem** (not event-log testing) are:

```bash
dpkg-query -W sudo cron openssh-client libpam-modules-bin acl apparmor kmod fdisk auditd
dpkg-query -L sudo openssh-client libpam-modules-bin apparmor kmod fdisk | grep -E '(sudoedit|ssh-agent|ssh-keysign|pam_timestamp_check|apparmor_parser|modprobe|/kmod$|/fdisk$)'
for p in /etc/sudoers /etc/sudoers.d /etc/cron.d /var/spool/cron /var/log/journal /var/log/sudo.log /var/log/lastlog /var/log/faillog /run/utmp /etc/security/opasswd; do test -e "$p" && echo "PRESENT $p" || echo "ABSENT $p"; done
```

If package/image access is unavailable, retain conditional rules as **unverified and not satisfied**, not N/A. Obtain approval for prerequisite installation or a documented exception. For Proxmox, do not assume that a local audit watch on `pmxcfs` (`/etc/pve`) captures all clustered changes; obtain supported Proxmox API/task/cluster telemetry. PVE 8 is out of vendor support; prioritize PVE 9/Debian 13.


## v0.16 — Selecting CVE and hunting rules

**Mandatory baseline (v0.19):** Install Tier 1 and all applicable Tier 2 rules. `29-system-config-integrity.rules` retains v0.17 targeted shell-startup watches and now adds an active recursive `/etc` write/attribute watch; confirm overlap, volume, and availability risk. An authorized waiver is required if the mandatory monitoring cannot be supported.

**CVE actions:** Confirm OS/package/kernel susceptibility using the relevant vendor advisory, then **patch or apply an approved mitigation**. If exposure persists or threat monitoring is required, select the matching `CVE-YYYY-NNNN.rules` from Tier 3; this **detects selected behavior only** and is not an effective substitute for patching. Do not copy all `CVE-*.rules` by wildcard. Copies of matching rules across two CVE files are intentional for individual selection, **not** authorization to load every copy. If multiple CVEs require identical rules, install one equivalent set and document both CVE requirements; account for overlapping keys and SPL filters. Rule keys such as `af_alg`, `splice_user` and `process_creation` must match the selected detection or be translated in SPL.

**PHP2Shell caveat:** `CVE-2026-109618.rules` and `CVE-2026-109619.rules` contain commented candidate `exe=` filters. Select and uncomment a candidate only if the exact web/application-server executable is installed and relevant to the workload. No default enabled syscall rule exists for this CVE family because blanket service-account execution collection could be excessive. These CVE-named files do not assume an additional endpoint product; their workload selectors must be explicitly configured for the applicable service. Both PHP CVE files implement the same process sensor; pick one when both apply.

**Ordering:** Stage selected CVE files and any approved conditional rule edits **before** installing finalization with `-e 2`; later activation/retirement of rules on an immutable host normally requires reboot/redeployment of the audit ruleset. Do not treat a duplicate add failure as evidence the kernel chose a valid preferred rule. Check the effective rule set and audit keys during deployment.

**CVE-independent hunting:** Monitoring every user's `.bashrc` or `.profile`, and sudoers read access, remains a targeted Tier 3/hunting decision, not a mandatory Tier 2 change. The SysRq procfs candidates in `29-system-config-integrity.rules` are also conditional until the kernel/image supports them.

## v0.19: Auditd-only Tier 2 configuration integrity

**Approved rule:** Every selected OS/architecture profile now contains active `-F dir=/etc -F perm=wa -k t2_etc_integrity` rules in `29-system-config-integrity.rules`. x86_64 uses both b64 and b32; ARM64 uses native b64. This does not rely on any non-auditd endpoint software.

1. **Loader-preload first creation:** A single-file watch cannot cover a file that is absent at rule load. The recursive `/etc` watch captures writes, creations, renames, and metadata changes under the directory when supported by the kernel/filesystem. Investigate `PATH` records for the precise target, including the loader preload configuration. This may not capture modifications in separate mount points or nonstandard loader paths; assess those separately.
2. **SSH and sudoers:** This new baseline provides auditd write/attribute visibility to `/etc/ssh`, `/etc/sudoers`, and `/etc/sudoers.d`, including file creation, *whether or not* optional packages are present at rule load time. Pre-existing targeted rules remain, even when they overlap, to preserve source mappings and audit keys; only enable additional commented exact-path watches when a path exists and has a documented need.
3. **Magic SysRq:** Persistent changes in `/etc/sysctl.conf` and `/etc/sysctl.d/` fall under the new `/etc` watch. They do **not** prove detection of a direct privileged write to `/proc/sysrq-trigger` or `/proc/sys/kernel/sysrq`. Procfs candidates remain commented pending verified kernel acceptance. An absence of SysRq events cannot be counted as successful monitoring; document that runtime limitation and seek an approved waiver if it is mandatory for the host.
4. **Collection cost:** A recursive watch is wider than the targeted rules it supplements. Before customer rollout, confirm the expected event rate and loss/backlog risk in the organization's workload acceptance process. Without host access these measurements cannot be certified. Audit failure mode remains `-f 2` (kernel panic on critical audit failures), and any inability to support Tier 2 must use an authorized, scoped exception rather than deleting it silently.
5. **Audit event transport:** Preserve native `SYSCALL`, `PATH`, `CWD`, `EXECVE`, and `PROCTITLE` records, event serial IDs and audit keys, and use the `PATH` records to filter `/etc/ld.so.preload`, sudoers, SSH and SysRq configuration changes in Splunk. This is **auditd telemetry**, not a requirement for an additional host monitoring agent.
6. **Cloud boundary:** Local auditd cannot provide an authoritative record of remote cloud API calls. Cloud-host API/security-group/IAM monitoring requirements must be handled at the cloud control plane, separately from host auditd.

**Linux Audit documentation:** https://man7.org/linux/man-pages/man8/auditctl.8.html ; https://github.com/linux-audit/audit-userspace ; **SysRq kernel documentation:** https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
