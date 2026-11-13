# Enterprise Linux Audit Policy — v0.19

**Status: ENGINEERING CANDIDATE — no profile is certified STIG-compliant or production-approved by this release.**

The package retains the v0.14 remediation of several *static* defects identified in the independent v0.11 validation report. **It does not close the remaining platform STIG-reconciliation, file-existence, optional cloud-agent package prerequisites, on-host event-generation, performance, or SIEM-validation gates.**


## v0.19 — Auditd-only host integrity baseline

- **Auditd is the sole mandatory host monitoring dependency.** No secondary endpoint monitoring software is required or specified to meet Tier 1/2 host-rule objectives.
- Activated a **recursive `/etc` write/attribute audit rule** in all 80 architecture variants of `tier-2-core-security/29-system-config-integrity.rules`: x86_64 adds `arch=b64` and `arch=b32`; ARM64 adds `arch=b64`. **120 new active directives**; existing active directives are preserved.
- The directory rule observes creation or modification of loader preload configuration even when the file did not exist at rule-load time. It also monitors SSH/sudoers changes regardless of whether their individual files exist when audit rules load; native `PATH` records are required to determine which file changed.
- Existing Tier 1/2 targeted SSH, sudoers, PAM and shell watches remain in place for their audit keys and compliance provenance. Overlap and extra audit volume must be assessed; do not assert performance acceptance from offline analysis. `-f 2` and `-e 2` are unchanged.
- **Magic SysRq:** persistent `/etc/sysctl*` file modifications are monitored; direct writes to procfs SysRq trigger/control paths are **not certified** from this ZIP. Their conditional `auditd` candidates remain commented until kernel-specific validation. A configuration watch does not demonstrate trigger attribution.
- **Cloud limit:** host auditd cannot observe remotely initiated cloud API, security-group, or IAM changes; any separate cloud control-plane requirements remain outside what an `auditd` ruleset can provide.
- README, all three existing guides, AGENTS.md and 2,000 rule headers updated. Engineering candidate, not host-tested or STIG-certified. Performance, file path, mount-point and kernel acceptance constraints remain applicable.

## v0.18 — Historical: SSH integrity expansion and source-selection decision

- **Activated targeted Tier 2 OpenSSH configuration subtree monitoring** (`-F dir=/etc/ssh -F perm=wa -k t2_ssh_change`) for Ubuntu 22.04/24.04/26.04 and RHEL 9 profiles in every available hosting environment: **16 OS/environment combinations × 2 architectures = 32 profile variants; 48 new active directives** (x86_64 b64+b32, ARM64 b64). The directory and package must exist on the deployed image. Other 48 variants remain conditional; applicability must be documented and enabled when OpenSSH is installed.
- **Sudoers:** The existing 32 profiles with active watches are unchanged. In the other 48, the watches are *conditional on sudo installation*; they are not silently considered covered. No blanket watches were activated that could reference missing files.
- **Loader preload:** First-time creation of a normally absent file is **not** captured by the inactive leaf watch. An unfiltered `/etc` recursive watch was *not* promoted to the mandatory Tier 2 baseline. Existing cloud-host rules include a narrower `auid=unset,euid=0,dir=/etc` sensor, which can observe only a subset of loader-related changes. At that release the issue was still open; **v0.19 supersedes that recommendation with active auditd-only `/etc` coverage.**
- **Magic SysRq:** `/proc/sys/kernel/sysrq` and `/proc/sysrq-trigger` serve different functions; `kernel.sysrq` does not block privileged use of `sysrq-trigger`. Kernel/procfs audit watch candidates remain disabled pending platform validation. Do not infer live-control coverage from persistent sysctl configuration watches.
- **Documentation and AGENTS.md:** corrected the stale handoff package reference and updated all guide titles. All existing active rules, all CVE-specific Tier 3 rules, and the settled `-f 2`/`-e 2` controls are preserved.
- **Validation:** Static comparison against v0.17 finds exactly 48 new active directives in 32 profiles, zero removed/modified active directives, and no additional directory-wide `/etc` rules (existing filtered cloud-host watches are unchanged). No host tests, production approval, or current-STIG re-certification is implied.

## v0.17 — Historical: targeted Tier 2 system startup integrity

- **Approved narrow, CVE-independent Tier 2 coverage** in all 80 implementations: audit modifications/attribute changes to `/etc/profile` and the OS-family system-wide Bash startup file (`/etc/bashrc` on RHEL-derived/Amazon/Oracle/Rocky/Alma; `/etc/bash.bashrc` on Ubuntu/Debian/SLES).
- Add `/etc/profile.d` subtree monitoring for RHEL-derived/Amazon/Oracle/Rocky/Alma, Ubuntu and SLES where vendor documentation supports it. On **Debian 12/13**, `/etc/profile.d` is **commented/conditional**, because Debian base-files does not guarantee that directory or its sourcing in `/etc/profile`.
- x86_64 variants include both `b64` and `b32` file-watch rules; ARM64 uses native `b64` only. **348 active audit directives added** across 80 variants. All previous active directives, keys, STIG watches, `-f 2`, `-e 2`, and CVE-specific Tier 3 files are preserved.
- **No broad `/etc` recursive watch was activated in v0.17 (superseded in v0.19).** The leaf-path candidate was inactive at that release because a missing file could not be watched. **v0.19 supersedes it with active parent-directory monitoring.**
- SSH/sudoers watches already exist in a subset of Tier 1 profiles; remaining OS-specific package-dependent targets remain conditional and must be verified against deployed image content. SysRq procfs candidates and user-home shell modifications remain inactive.
- **Active-file inventory:** 1,804 of 2,000 `.rules` files contain active directives; **196 files remain comment-only** (160 PHP2Shell CVE, 28 on-prem cloud stubs, 8 conditional MAC-policy). Previous release notes below record the historical v0.16.x count of 276 before the 80 Tier 2 proposal files acquired active watches.
- Release state remains **engineering candidate**. Standard vendor paths do not guarantee presence on every minimal/custom image. No host-load, event generation, EPS, or Splunk collection validation was performed.

## v0.16.4 — Ubuntu 22.04 published-source reconciliation (no active rule change)

- Reconciled **49 V2R10 audit-rule V-IDs** with active Tier 1/Finalize rule coverage in all eight Ubuntu 22.04 implementations; full crosswalk is in `docs/03-RULE-SOURCING-AND-MAINTENANCE.md`.
- Corrected Ubuntu 22.04 source-provenance wording and documented conditional paths and the cron-watch limitation.
- The official V2R10 ZIP/XCCDF was not independently obtained or hash-verified. This is **not** a compliance certification or host-test result.
- **All 2,000 rule files retain exactly the same active directives as v0.16.3.** Tier 2 configuration-integrity candidates remain disabled; Tier 3 CVE selections and `-f 2` are unchanged.

## v0.16.3 — inactive Tier 2 proposal clarification (no audit behavior changes)

- **Resolved recurring false positive:** every `29-system-config-integrity.rules` file contains exactly **one** textual `/etc/ld.so.preload` occurrence, on one **commented-out** (inactive) leaf-path audit rule. The other comments describe applicability without repeating the path. Previously the same path appeared four times in comments but represented only one candidate, not duplicate rules.
- The broad `/etc` integrity proposal and the loader leaf-path alternative both remain **inactive**, pending a separate Tier 2 promotion/collection-volume decision. No Tier 2 collection was added.
- Standardized release metadata and the three existing guide titles to `v0.16.4`. All **2,000 active rule directive sequences match v0.16.2 exactly**; the settled `-f 2` and `-e 2` controls, tiers, and all 80 architecture variants are unchanged.
- Reviewers must count **actual rule directives**, not plain-text occurrences within explanatory comments, when reporting duplicates. The AI handoff `AGENTS.md` records this as a resolved issue.

## v0.16.2 — header-format normalization (no active directive changes)

- Standardized the first-line `# TARGET ARCHITECTURE: ... | v0.16.2 | <environment>/<os>` header in **all 2,000** `.rules` files. In particular, added that header to **80 inactive Tier 2 `29-system-config-integrity.rules` proposals** and **480 CVE-named Tier 3 rule files**, retaining their original descriptions and selectors.
- Synchronized rule release metadata, README, and all three existing guide titles to `v0.16.2`. The `AGENTS.md` AI handoff is maintained separately and is not a fourth customer guide.
- **Zero active audit directives changed** from v0.16.1. No file names, rule locations, OS/cloud/architecture profiles, candidate activation status, or `-f 2`/`-e 2` settings were changed. The package remains an **engineering candidate**, not production-approved.

## v0.16.1 — housekeeping-only release (no active directive changes)

- All **2,000** `.rules` files have consistent `v0.16.1` target-architecture release headers. The 28 RHEL 9 ARM64 Tier 1 files now place the target-architecture header first; the historical ARM translation/provenance comment remains intact beneath it.
- Removed the duplicate **commented** `/etc/ld.so.preload` leaf-watch proposal from all 80 copies of `29-system-config-integrity.rules`. The remaining proposal is still **inactive** pending approval and noise/overlap analysis.
- Updated all three guide title headings to `v0.16.1`.
- Added a comment to every `00-audit-foundation.rules` identifying `18-security-critical.rules` as the location of the **unchanged, active** `-f 2` fail-secure setting. Keep these files together during implementation.
- **Inventory clarity:** 25 `.rules` files per implementation is a file count, **not** 25 active sensors. Of 2,000 files, **276 contain no active audit directives** (80 `29-system-config-integrity.rules`; 80 each `CVE-2026-109618.rules` and `CVE-2026-109619.rules`; 28 on-prem `27-cloud-host-security.rules`; eight conditional `14-mac-policy.rules`). These commented-only files remain included intentionally and must not be described as active collection. Different profiles may have other commented candidate lines within active files.
- **No active audit directives were changed**, no directory layout was altered, and all 80 profiles retain `-f 2`. Applicability, STIG reconciliation, and host validation gates remain open.

## v0.16: CVE-specific Tier 3 + CVE-independent Tier 2 integrity

- Replaced `31-cve.rules` with **six separately named, threat-directed files** per architecture/profile: `CVE-2026-31431.rules` (Copy Fail), `CVE-2026-43284.rules` and `CVE-2026-43500.rules` (Dirty Frag), `CVE-2026-74580.rules` (failed SOCK_RAW), and `CVE-2026-109618.rules` / `CVE-2026-109619.rules` (PHP2Shell). Generic `30-exploitation.rules` is unchanged.
- **Tier 3 is not an automatic install.** Select ONLY CVE files that apply to an exposed/affected asset and have a threat-monitoring requirement. Where several CVEs share equivalent collection, choose one sensor rule implementation rather than installing identical candidates together. Auditing **does not remediate** a CVE: vendor patches or mitigations remain the primary response. Splunk searches may require audit-key adaptation.
- PHP2Shell files intentionally contain **commented service-binary selectors** pending installed-package/workload confirmation; do not treat them as enabled sensors merely because the file exists. These are workload-specific auditd rules; select only for relevant web/application services.
- Added `29-system-config-integrity.rules` as an **inactive Tier 2 proposal** for **write/attribute activity under `/etc`**. If promoted and enabled, it would cover creation of `/etc/ld.so.preload`, shell system profiles, SSH/sudoers and other CVE-agnostic security configuration, even when an individual target file is missing at startup. This would be a broad directory rule: it is **commented out pending collection-volume and duplicate-overlap review** and must not be described as deployed Tier 2 coverage.
- Magic SysRq procfs watches are **conditional candidates**, not active defaults, because presence and behavior vary by kernel/image. Per-user shell startup hunting and sudoers **read** monitoring remain Tier 3 candidates requiring workload scoping; no fleet-wide home read watches were added.
- **CVE-2026-111497** is a Brotli decoder vulnerability, **not** Dirty Frag; it has no fabricated auditd kernel-splice rules in this release.

## v0.14 offline package and path verification (no running host required)

This release also checks published Ubuntu generic cloud-image manifests and Amazon Linux standard/minimal AMI package comparisons. The cited generic Ubuntu 24.04/26.04 cloud images do not list `auditd` or `acl`; AL2023/AL2027 minimal AMIs do not list SSM Agent.

This release adds vendor-package evidence and explicit prerequisites for Ubuntu 22.04/24.04/26.04, Debian 12/13, and cloud guest-agent paths. Ubuntu 26.04 `apparmor_parser` watches now target the `/usr/sbin` packaged location. Ubuntu 24.04 STIG-derived rule lines, including `/var/log/sudo.log` and `/sbin/unix_update`, are **unchanged**: each is now annotated with the necessary image/path prerequisite; the former may not exist by default and will block direct loading. GCP host files add **conditional** `.template` and guest-agent plugin-state watches. Provider-specific conditional watches are not assumed installed.

**This is not a universal no-touch drop-in.** A distribution's package manifest identifies the path shipped by a package, *not* whether that package or a dynamically-created file is present in any given cloud/golden image. The 80 variants remain engineering candidates, not production-approved or STIG-certified. See the existing guides for the offline acceptance gate and required customer applicability/exception decisions.

## v0.14 — Ubuntu 22.04/26.04 and Debian baseline remediation

- **Ubuntu 22.04 (8 architecture/hosting variants):** Expanded Tier 1 from the comprehensive Ubuntu 24.04 *audit objectives* (account management, privilege binaries, access failures, kernel modules, login records, sudoers, journald, cron), and ACTIVATED `/sbin/apparmor_parser` under V2R10 **UBTU-22-654010 / V-260604**. Retained separate `-e 2` in Finalize (**V-288816**). **Do not claim 49/49 verified V-ID coverage:** the user's SHA256 `2229b5be…` source archive was described but not supplied to this run, and a full machine-readable XCCDF audit extraction was not available for an exact rule-by-rule comparison.
- **Ubuntu 26.04 (8 variants):** Now inherits the full Ubuntu 24.04 Tier 1 engineering objectives, with native Ubuntu 26.04 `/usr/sbin/apparmor_parser`. This is **not** a published 26.04 STIG mapping; inherited rules contain optional-path prerequisites and require native 26.04 image inspection.
- **Debian 12/13 (8 variants):** Added account-admin and privileged binary execution, session/logon record watches, root xattr auditing, and denied-file access expansion. Package-dependent `sudo`, `cron`, `acl`, SSH, PAM helper, and AppArmor watches remain **conditional** so a minimal install is not guaranteed to load them. These are **Debian enterprise objectives**, not a Ubuntu product STIG certification.
- **Proxmox VE:** Debian profile is a starting point, not drop-in proof. The Proxmox `/etc/pve` configuration mount uses `pmxcfs` (FUSE) and must not be assumed to behave as an ordinary auditd file watch. Use supported platform/API/task/cluster logging as companion evidence; do not install the Ubuntu 24.04 STIG as if it applies to Debian.
- The remaining OS profiles, all Tier 2 rules, Tier 3 and cloud-host rules are unchanged in active semantics. **No profile is production-approved.**

**Offline prerequisites:** Presence of an executable in a vendor repository is not evidence it is installed on the deployed image. `/var/log/sudo.log`, `/var/log/faillog`, `/var/log/journal`, `/var/spool/cron` and optional utilities may be absent. Resolve via approved image prerequisites or documented exception before loading the package.

**Authorities:** <https://www.cyber.mil/stigs/>, <https://www.cyber.mil/stigs/stig-announcements>, Ubuntu 22.04 V2R10 archived check/fix text at <https://cyber.trackr.live/stig/Canonical_Ubuntu_22.04_LTS/2/10>, Proxmox admin guide <https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf>.

## What is in the package

- 40 OS/hosting-environment combinations: on-premises, AWS, Azure and GCP.
- **Two mutually exclusive architecture choices per OS/environment:** existing profile root is **x86_64**; its nested `aarch64/` subtree is **ARM64**. A total of **80 architecture-selectable implementations**, 25 `.rules` files each (2,000 `.rules` files).
- Exactly three documents under `docs/`, plus this README and the rule files. No deployment script, generated combined rule file, new catalog, or automation is bundled.
- **Tier 1 + Tier 2 mandatory** under the enterprise Minimum Security Requirement (MSR), Tier 3 as threat-directed, Finalize last.

## Choose the exact rule directory

```text
rules/
  on-prem/<os-version>/                  # x86_64
  on-prem/<os-version>/aarch64/          # ARM64
  aws/<os-version>/                      # x86_64
  aws/<os-version>/aarch64/              # ARM64
  azure/<os-version>/                    # x86_64
  azure/<os-version>/aarch64/            # ARM64
  gcp/<os-version>/                      # x86_64
  gcp/<os-version>/aarch64/              # ARM64
```

In each selected directory (at either architecture level):

```text
tier-1-baseline/        00-foundation; 10-14 OS/compliance; 18-failure-control
tier-2-core-security/   20-28 active SOC/IR; 29 configuration-integrity candidate
tier-3-threat-specific/ 30-exploitation + individually selected CVE-YYYY-NNNN.rules
finalize/               99-finalize.rules (-e 2; last)
```

**DO NOT** copy both the root and `aarch64/` rules, recursively install the parent profile, or combine multiple OS/environment profiles. Copy only the tier directories for the selected architecture to the host's audit rule directory after validation.

### Supported OS and environment candidates

| Hosting environment | OS directories |
|---|---|
| on-prem | `rhel8`, `rhel9`, `rhel10`, `almalinux9`, `rocky8`, `rocky9`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `oraclelinux8`, `oraclelinux9`, `sles15`, `debian12`, `debian13` |
| AWS | `amazon-linux-2023`, `amazon-linux-2027`, `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `almalinux9`, `oraclelinux9`, `rocky9` |
| Azure | `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `sles15`, `almalinux9`, `oraclelinux9` |
| GCP | `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `debian12`, `debian13`, `rocky9` |

**Amazon Linux 2027:** preview-only candidate pending general availability, supported image testing, and official/approved compliance mapping. **Ubuntu 26.04:** engineering candidate; do not apply Ubuntu 24.04 STIG V-IDs as if they were a Ubuntu 26.04 product STIG.

## Changes inherited from v0.12 and v0.13 (relative to v0.11)

1. **ARM64:** Added a complete `aarch64/` subprofile for every listed OS/cloud profile; translated unsupported legacy x86 syscall names to native ARM64 `*at` / `*at2` equivalents where appropriate and removed x86-only b32 rules. Architecture mapping is tested against the Linux Audit syscall-name library, *not* against every guest kernel.
2. **Execution:** Added explicit `execveat` coverage for interactive and root execution, and privilege-transition coverage. Added x86_64 b32 counterparts to additional syscall telemetry for hosts supporting the compatibility ABI.
3. **Ubuntu 24.04:** Preserved the 64 exact source directives from the user-supplied Ubuntu 24.04 V1R7 extraction on each x86_64 profile; ARM64 is a *translated engineering candidate*, not an exact DISA x86 fix-text match.
4. **RHEL 9:** Added the 81 source directives from the previously assembled **RHEL 9 V2R10 reference package**, including missing privileged command, permissions, identity, module, and cron coverage, with per-line reference comments. The older local reference is **not independently verified against the latest authoritative DISA release** and contains paths requiring image-specific prerequisites.
5. **Other systems:** Added enterprise baseline changes for audit/PAM files, identity resolution, modern access/deletion/permission syscalls, and mount/group privilege operations. These are not substitutes for product-specific STIG mapping.
6. **Cloud guests:** Added active auditing of root daemon execution (`execve`/`execveat`), daemon outbound connection attempts, and noninteractive root `/etc` changes. Provider-specific SSM/waagent/Google guest-agent/CLI/credential watches remain **explicit conditional requirements**, since a hard-coded watch against a missing file can fail to load. Exact cloud API operations **require cloud-native logs**.
7. **Documentation:** Updated deployment, architecture selection, live validation, cloud logging, risk/waiver decisions and source maintenance. All user-supplied v0.11 files remain the baseline for this revision.


## v0.15 targeted review corrections (relative to v0.14)

- **Debian 12/13:** Added both-architecture auditing of root-session kernel-module syscalls and x86_64 b32 privilege-transition coverage. Added source-linked conditional candidates for `modprobe`, `kmod`, `fdisk`, cron directories, persistent journal, and sudo file logging. The existing sudo, SSH, ACL, PAM and AppArmor candidates remain conditional on installed packages. **Do not claim active Ubuntu-rule parity:** absent files and optional packages can prevent audit rules from loading.
- **Proxmox:** PVE 8 uses Debian 12 and is beyond upstream Proxmox support as of August 2026; PVE 9 uses Debian 13. Debian base profiles are engineering candidates, not Proxmox-specific certified policies. PVE cluster configuration under `/etc/pve` is `pmxcfs`; pair host audit with Proxmox API/task/cluster logs. No unconditional FUSE watches were introduced.
- **Ubuntu 22.04:** Replaced inaccurate V-ID references (`useradd` **V-288815**, cron **V-274862**) and inserted per-rule V2R10 objective mappings where a matching audit objective can be identified. `-e 2` carries **V-288816** in Finalize. These are source **traceability references**, not an independently verified full DISA XCCDF check/fix equivalence assessment.
- **Provenance:** Normalized the package-version header to `v0.15` in **all 1,520 `.rules` files**, retaining historical comments describing earlier releases. No rule was silently removed or any fail-secure setting downgraded.
- **Availability:** `-f 2` remains unchanged. A local `-f 1` deviation requires explicit approval and cannot be inferred from this review.

## Security and operational gates — not resolved by static tests

- **STIG completeness:** Ubuntu 24.04 has review-derived x86_64 source-line reconciliation; Ubuntu 22.04 has 49/49 V2R10 audit-rule V-IDs mapped against publicly readable check/fix text, but not independently hash-verified against the official DISA archive or host-tested; RHEL 9 has a prior local reference (81/81). Other OS versions require current product-specific DISA STIG/SRG checks, file/path applicability, and V-ID-level evidence. **No profile can be represented as fully STIG-validated.**
- **Missing paths:** `auditctl`/`augenrules` can reject `-w`, `path=`, and `dir=` watches if referenced files/directories are absent. The Ubuntu and RHEL 9 source-based candidates in particular contain required-path watches that may be absent on minimal images. Validate and resolve through prerequisite installation, approved N/A, or exception **before loading**.
- **Cloud guest agents:** Mandatory provider-specific agent/credential/CLI monitoring is conditional on what is installed. The generic root daemon rules are **not** equivalent to exact agent configuration watches. An applicable but inactive agent watch needs remediation or an approved exception.
- **Cloud control plane:** CloudTrail (AWS), Azure Activity Log (Azure), and Cloud Audit Logs (GCP) are mandatory companion sources for security-group/NSG/firewall, role/IAM, and API changes. `auditd` cannot record remote management-plane operations directly.
- **Live tests:** None of these 80 architecture-specific candidates was kernel-loaded, end-to-end event-tested, performance-tested, or Splunk-validated as part of offline packaging.
- **Availability:** `-D` clears existing audit rules; `-f 2` may panic on critical audit failure; `-e 2` makes rules immutable until reboot. Assess with the appropriate authority before any production deployment.
- **Volume:** Tier 2 `execve`, `execveat`, filesystem changes, `connect`, and daemon network monitoring can be expensive. Performance failures require remediation/tuning within the required security objective or an approved waiver.

See `docs/01-IMPLEMENTATION-GUIDE.md` for safe selection/staging, `docs/02-MINIMUM-SECURITY-REQUIREMENT-AND-WAIVER.md` for exceptions, and `docs/03-RULE-SOURCING-AND-MAINTENANCE.md` for official sources and refresh instructions.

## 10. Carry-forward work queue (not authorization to implement)

The following work remains open. This summary mirrors **AGENTS.md §10**; it does not authorize changes to mandatory rules or expand Tier 3 by itself.

1. **Tier 2 directory-integrity validation:** Assess active recursive `/etc` write/attribute monitoring for coverage across mount points, overlap with targeted watches, event volume, and audit backlog. Direct Magic SysRq procfs auditing remains conditional and unverified.
2. **Tier 3 non-CVE hunts:** Evaluate user shell initialization changes, sudoers read access, and service-scoped investigations separately. Do not promote a hunt to mandatory Tier 2 solely because a Splunk analytic uses it.
3. **CVE-specific rule applicability:** Recheck CVE references, affected OS/kernel versions, overlapping telemetry, and the currently inactive PHP2Shell executable selectors. Preserve the distinct `CVE-YYYY-NNNN.rules` files.
4. **OS-specific STIG and path verification:** Continue authoritative Ubuntu 22.04 V2R10 reconciliation and platform-specific mapping for RHEL, AlmaLinux, Oracle Linux, SUSE, Amazon Linux, and other supported profiles. Validate package/image path prerequisites and conditional cloud agents without claiming host testing or compliance.
5. **Release traceability:** Keep rule architecture/version headers, README, `AGENTS.md`, and all three guide titles synchronized in subsequent releases.

For detailed AI maintenance instructions and the current policy decisions, see `AGENTS.md`. All profiles remain **engineering candidates** until applicable validation gates are satisfied.
