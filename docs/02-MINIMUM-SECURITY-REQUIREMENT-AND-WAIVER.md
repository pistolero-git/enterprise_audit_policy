# 02 — Minimum Security Requirement and Waiver | v0.18

## v0.17 — CVE-independent Tier 2 shell-startup baseline

Active system-wide shell startup watches in `29-system-config-integrity.rules` are now part of mandatory **Tier 2**: `/etc/profile`, distribution-specific global Bash startup file and `/etc/profile.d` where it is a supported default. On Debian, `/etc/profile.d` is conditional because it is not guaranteed as a standard default and is not always sourced. **A nominal file presence does not prove a rule loaded.** Missing applicable paths must be provisioned or handled through the existing authorized applicability/waiver process.

No `/etc`-wide integrity watch or `/etc/ld.so.preload` leaf watch was made active. Therefore this change **does not close initial creation monitoring for absent loader configuration**, which needs a separately justified broad watch or other file-creation telemetry. No CVE-specific Tier 3 rule is promoted to Tier 2. Audit failure `-f 2` remains settled Tier 1 policy.


## v0.16.4 — Ubuntu 22.04 STIG coverage boundary

**Ubuntu 22.04 V2R10 (v0.16.4 offline mapping):** All **49 published audit-rule-related V-IDs** are represented by active Tier 1/Finalize directives in all eight Ubuntu 22.04 variants, including the AppArmor parser, cron watches, useradd and immutability. This is a source-to-rule presence/intent cross-check, **not** official DISA ZIP hash verification, host-load evidence, or overall STIG compliance. Mandatory watches with missing-file/package prerequisites still require remediation or an approved exception. See the full 49-row traceability table in Document 03.

## Mandatory scope

The enterprise **Minimum Security Requirement (MSR)** for each governed full Linux host/VM (on-prem, AWS, Azure, or GCP) is:

- **Tier 1 Baseline:** audit foundation and all applicable *product/version/architecture* STIG or approved SRG audit requirements; identity, authorization, privileged execution, filesystem, MAC policy and audit-system controls.
- **Tier 2 SOC/IR:** process execution including `execveat`, credentials, persistence, file operations, privilege, local network connections, security configuration, and provider-specific cloud-host telemetry for cloud instances. Cloud management/API/identity logs are a **mandatory companion capability**, even though they are collected outside auditd.

**Tier 3** is required when directed for a specific threat, exploit/CVE, or incident. **Finalize** is applied last as required/approved (`-e 2`). An OS directory existing in this ZIP does not establish compliance; the correct architecture-specific profile and image-specific STIG/application validation are required.

## A mandatory requirement is not the same as a universally present file

Before loading, each active `-w`, `path=`, and `dir=` watch must resolve on that host. If a mandatory STIG requirement refers to a missing component, determine whether the component must be installed or the requirement is *not applicable*. Do not silently comment a mandatory rule or call an absent audit event covered. An applicable missing file/path, disabled guest agent watch, or unsupported syscall requires a documented remediation or approved exception.

- **x86_64 vs ARM64:** use only the selected architecture's rules. ARM64 mappings of x86 source text are engineering candidates; demonstrate security objective equivalence and check the platform's authorized compliance baseline.
- **Cloud guests:** always enable applicable provider guest-agent, automation, credential/CLI watches after actual installed-path validation. Generic `auid=unset` daemon telemetry does not replace exact agent monitoring or cloud-native API logging.
- **MAC:** SELinux/AppArmor policy watches do not enforce MAC and do not prove AVC/denial records are delivered. Validate MAC mode, package/service prerequisites, and the forwarding path separately.

## Waiver and exception triggers

An approved waiver is required when an applicable Tier 1/Tier 2 capability cannot be supported, cannot be loaded, fails to generate/forward events, creates persistent audit loss, or causes demonstrated unacceptable workload impact after engineering remediation. Absence of a genuinely optional/uninstalled cloud agent may be **N/A** *if an authorized applicability decision establishes that the agent/control is not required on that image*.

If the requirement is derived from a DoD STIG/SRG, the **AO/compliance exception process** (including POA&M/accepted-risk as applicable) is separate from, and not replaced by, an enterprise security waiver. Both authorities must be satisfied when both apply. An unexpected cost increase or alert volume alone is not authorization to disable mandated telemetry.

**Fail-secure policy:** `-f 2` is retained in v0.14. Depending on the audit failure mode it can panic the kernel. It is not appropriate to globally replace it with `-f 1` without the authorized risk/compliance decision. **Immutability:** `-e 2` prevents further rule changes until reboot. **Rule reset:** `-D` affects existing vendor/EDR rules. All require predeployment risk review.

## Rollout and stop criteria

1. Confirm applicable STIG source, OS image, CPU architecture, kernel audit support and installed file paths.
2. Test Tier 1 and Tier 2 in a disposable instance, and verify audit-rule loading and event generation before finalization.
3. Conduct canary and peak-workload measurements (EPS/GB/day, audit loss/backlog, CPU/I/O and app SLOs), then verify complete Splunk ingestion and cloud-native management logs.
4. **Stop rollout** on audit loss, sustained backlog exhaustion, unapproved missing mandatory rules, insufficient data forwarding, or unacceptable service degradation. Correct, scope and re-test without losing the mandated objective. If still unsupported, submit a waiver and compensating-control plan.
5. Mark a profile approved **only for the particular tested image/version/architecture/cloud environment** once acceptance evidence and authority are recorded. Approval does not extend to every kernel, image, or cloud SKU of the same OS.

## Required waiver record

Record at least: host/asset owner; OS/image/kernel; architecture; provider/account/subscription/project; specific rule, requirement and STIG V-ID; missing capability and root cause; audit `lost`, backlog, EPS, CPU/I/O and business SLO evidence; SIEM visibility/detection impact; cloud API log coverage; compensating controls; remediation owner and action dates; residual risk; AO and enterprise approvals; ticket; approved start, expiration, and reevaluation triggers.

**Tier 3:** when required but unsupported, escalate to the designated incident/threat authority for time-bounded disposition. All exceptions must be reviewed after agent changes, image updates, new STIG releases, material workload changes, or a new kernel/architecture.

## Current v0.14 evidence status

- **Ubuntu 24.04 x86_64:** source-line matching against the supplied V1R7 extraction, not a passed STIG audit.
- **RHEL 9 x86_64:** prior local V2R10 reference line matching, not independent current DISA validation.
- **All other OS profiles and ARM64 versions:** product-specific applicability and STIG/approved-SRG mapping incomplete.
- **All 80 architecture selections:** not yet loaded and tested on representative target hosts; not production-approved by this package alone.
- **Amazon Linux 2027:** preview engineering profile; do not label production-ready.

## v0.14 — Missing default paths and package-dependent STIG audit directives

Lack of a package or a generated file on a published minimal image does **not** automatically mean a mandatory STIG/enterprise audit requirement is not applicable. Document the rule/V-ID, prerequisite package or configured file, package-manifest evidence, exact OS image/version/architecture, owner, impact on collection, substitute telemetry if approved, waiver authority, expiry, and remediation date. If a required STIG watch cannot load, do not mark Tier 1 satisfied or automatically delete it. For Ubuntu 24.04, `/var/log/sudo.log` is a concrete example of a required deployment prerequisite rather than a universal default.

## v0.14 — Baseline minimum and waivers: Ubuntu and Debian gaps

**N1 (Ubuntu 22.04 V2R10; historical v0.14 assessment, superseded by the v0.16.4 published-source mapping above):** The former sparse profile was replaced with a broader Tier 1 candidate reflecting the Ubuntu 24.04 audit objectives but with Ubuntu 22.04 specific AppArmor parser activation (`/sbin/apparmor_parser`, V-260604). V2R10 immutability (V-288816) remains in Finalize. Obtain and preserve the original official V2R10 archive SHA256 (review references `2229b5be…` but that archive was not included in this task), extract the full audit rule-bearing V-IDs, compare all check/fix requirements, and document remaining differences. **Do not state full 49/49 verified STIG coverage.**

**N2 (Ubuntu 26.04):** The Tier 1 directives now match the Ubuntu 24.04 *engineering objectives* except for release-specific AppArmor handling and documented prerequisite assumptions. They must **not** be labeled an Ubuntu 26.04 DISA STIG baseline. Assess the exact current vendor package/image manifests and do not silently ignore missing watches.

**N3 (Debian 12/13 and Proxmox):** Added explicit user/privileged-command monitoring, login-record watches, and file-access objectives using Debian-specific path assumptions. Commands from packages not universally present (`sudo`, `acl`, PAM helpers, `openssh-client`, `cron`, AppArmor) remain commented as **conditional** requirements pending package installation or verified applicability, not automatically N/A. For Proxmox, `/etc/pve` is a `pmxcfs` FUSE filesystem; do not presume that ordinary auditd watch semantics cover its clustered configuration. Pair host audit with supported Proxmox task/API/cluster log sources.

**Acceptance rule:** These changes improve *engineering coverage* and remove the misleading parity assumption; they do not substitute for source V-ID reconciliation, image-path checks, kernel loading, event evidence or the organizational waiver process.

## v0.15 — Mandatory coverage versus disabled candidates

A `#`-commented audit rule is **not deployed** and may not be counted as implemented coverage. If the corresponding software is installed (sudo, OpenSSH, PAM helper, cron, AppArmor, kmod, fdisk, ACL), activate the matching command/path rule after confirming the real path or document approved alternative coverage / waiver. Absence of a legacy log file is not automatic permission to mark a monitoring requirement N/A. If sudo file logging or persistent journald is required, provide and validate the configuration prerequisite.

The default package keeps `-f 2` and `-e 2` unchanged. Requests for `-f 1` on a homelab, appliance, or availability-sensitive host require a separate system-specific approved waiver, with scope, compensating telemetry and expiration.

## v0.16 — CVE response and Tier 3 monitoring

A Tier 3 CVE file is a *detection option*, not a patch, workaround, or compensating control unless separately assessed and accepted by the security authority. For each affected asset record its patch/mitigation status, CVE(s), applicable Tier 3 file, date/owner, detection key or Splunk search dependencies, and activation/retirement decision. If multiple CVEs share rules, recording both CVEs with one approved sensor is acceptable; forcing duplicate rule installation is not required. The proposed Tier 2 `/etc` directory-integrity watch has **not** been activated or promoted into the mandatory baseline. Its future adoption requires an approved scope/performance decision.

## v0.18 — Security-configuration monitoring decisions

- OpenSSH configuration modifications are a CVE-independent mandatory Tier 2 objective **where OpenSSH is installed**. An absent package may be N/A with evidence; an installed package with an inactive watch is a coverage gap until remediated or formally excepted.
- Sudoers modification monitoring remains mandatory **where sudo is installed and applicable**. Do not claim conditional/commented watches satisfy this objective.
- Preload-file initial creation is not guaranteed by the baseline auditd leaf-watch approach. A separately validated EDR/Sysmon file-creation source is the preferred complement; missing required visibility must be assessed under the normal waiver/exception process. An unapproved unfiltered `/etc` auditd watch is not a substitute for documented engineering review. Existing cloud-host `auid=unset,euid=0` `/etc` watches cover only that filtered population.
- SysRq candidate watches remain conditional; do not claim that `kernel.sysrq` configuration monitoring alone detects direct privileged writes to `/proc/sysrq-trigger`.
- Tier 1 audit failure policy `-f 2` and Tier Finalize immutability `-e 2` remain unchanged.
