# AGENTS.md — Enterprise Linux Audit Policy

> **Purpose:** Portable handoff instructions for AI coding/review agents working on this Linux `auditd` policy project. Read this file, the current package `README.md`, and all three `docs/` guides before changing rules. Treat statements here as project decisions, **not** proof that an individual host or STIG requirement is compliant.
>
> **As of:** 2026-11-12  
> **Current release:** `enterprise-audit-policy-v0.17.zip`  
> **Release state:** **ENGINEERING CANDIDATE**. No OS/cloud/architecture profile is certified STIG-compliant, tested on a representative host, or production-approved.

## Ubuntu 22.04 V2R10 reconciliation status (v0.16.4)

All 49 published audit-rule-related V-IDs are mapped to active directives in the eight Ubuntu 22.04 implementations. The exact 49-row table is in `docs/03-RULE-SOURCING-AND-MAINTENANCE.md`. This **closes the missing audit-rule-ID inventory gap**, but **does not** close official DISA ZIP/XCCDF hash verification, conditional image path/package prerequisites, kernel loading, or actual STIG compliance. Do not reopen the "missing 49 audit-rule IDs" issue without naming a specific V-ID and demonstrating a missing or semantically invalid *active* directive. Continue reporting legitimate unverified deployment and official-source checks. Tier 2 `29-system-config-integrity.rules` now has narrowly scoped **active** system shell startup watches; its broad `/etc` and loader candidate watches remain disabled. Do not promote the broad watch without an explicit security/performance decision.


## v0.17 Tier 2 integrity policy decision — active targeted shell watches

**Decision:** CVE-independent modifications to system shell initialization are **mandatory Tier 2**; the broad `/etc`-directory proposal remains *inactive*. Each implementation now contains active watches under `29-system-config-integrity.rules` for `/etc/profile`, its platform Bash initialization path (`/etc/bashrc` on RHEL-family/Amazon, `/etc/bash.bashrc` on Ubuntu/Debian/SLES) and `/etc/profile.d` for non-Debian profiles. Debian's `profile.d` watch remains commented because base-files does not guarantee it. No per-user home dotfile watches were activated. Exactly **348 active rules added** across the 80 variants; otherwise active directives unchanged from v0.16.4.

**Do not re-open settled issues:** `/etc/ld.so.preload` is intentionally a single commented candidate; it cannot observe creation of a missing file. Neither a broad `/etc` watch nor SysRq procfs watches were activated. SSH/sudoers watches are already active in some Tier 1 profiles, but others still need package-specific validation. Never claim all these objectives are complete merely because the shell-init watches are active. The settled `-f 2` placement/policy and separate CVE-named Tier 3 files remain unchanged.

**Path evidence:** Default directory or binary paths are supported by published vendor docs/package manifests, *not* proven present on every golden/minimal image. `path=` and `dir=` watches require an existing target; check package/image inventories and handle N/A/waiver as prescribed. No host logs or kernel-loading evidence are available.

## 1. Project objective and boundaries

Produce a comprehensive, maintainable enterprise **Linux Audit Policy** for on-premises and cloud-hosted Linux systems. It must support:

- Applicable OS/version/architecture STIG or authorized SRG audit requirements.
- Consistent, useful SOC detection and incident-response telemetry (Splunk Enterprise Security / risk-based alerting).
- Independently selectable, **CVE-named** exploit-detection rules for assets pending patching or needing targeted monitoring.
- Straightforward deployment by selecting the **exact hosting environment, OS release, and CPU architecture**. The delivered profile must not require customers to assemble generic overlays.
- Source traceability, default-path/package prerequisites, exceptions and periodic maintenance.

**Do not** add deployment scripts, generators, standalone compliance catalogs, combined `.rules` outputs, extra policies, or new documentation types unless specifically asked. The established deliverables are the rule tree, `README.md`, and three existing guides. An `AGENTS.md` is a development handoff file, **not** a new mandatory customer deliverable.

**Do not** assume that a path present in a package repository exists on a given minimal, golden, cloud or customized image. **No real-host testing is available in this workflow**. Report offline findings accurately and leave host-dependent claims unverified.

## 2. Source of truth, layout, and inventory

Use the **latest actual ZIP contents**, not an earlier assistant description, as source of truth. For v0.17 the ZIP was inspected: it passes `ZipFile.testzip()`, contains **2,000 `.rules` files** and **4 non-rule files** (README + three guides). It has **40 OS/hosting combinations**, **80 architecture-selectable implementations** and **25 `.rules` files per implementation**.

```text
enterprise-audit-policy-v0.17/
├── README.md
├── docs/
│   ├── 01-IMPLEMENTATION-GUIDE.md
│   ├── 02-MINIMUM-SECURITY-REQUIREMENT-AND-WAIVER.md
│   └── 03-RULE-SOURCING-AND-MAINTENANCE.md
└── rules/
    ├── on-prem/<os-version>/
    ├── aws/<os-version>/
    ├── azure/<os-version>/
    └── gcp/<os-version>/
```

- **x86_64**: rules in the **immediate** tier directories of `rules/<environment>/<os-version>/`.
- **ARM64 (`aarch64`)**: a separate, complete implementation in the nested `rules/<environment>/<os-version>/aarch64/`.
- Both architecture choices contain their own `tier-1-baseline/`, `tier-2-core-security/`, `tier-3-threat-specific/`, and `finalize/`.
- **Never recursively install a profile directory**, because that would combine mutually exclusive x86_64 and ARM64 sets. Never combine different OS or cloud profiles.
- **Count interpretation:** 25 rule files per implementation includes **comment-only candidates**: 196 of 2,000 files are comment-only (160 PHP2Shell CVE files, 28 on-prem cloud-host stubs, eight conditional MAC-policy files). In v0.16.x the count was 276 before activating 80 Tier 2 `29-system-config-integrity.rules` files. File count does not indicate active sensor coverage.

**Profile inventory in v0.16.2:**

| Environment | OS directories |
|---|---|
| On-prem | `rhel8`, `rhel9`, `rhel10`, `almalinux9`, `rocky8`, `rocky9`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `oraclelinux8`, `oraclelinux9`, `sles15`, `debian12`, `debian13` |
| AWS | `amazon-linux-2023`, `amazon-linux-2027`, `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `almalinux9`, `oraclelinux9`, `rocky9` |
| Azure | `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `sles15`, `almalinux9`, `oraclelinux9` |
| GCP | `rhel9`, `rhel10`, `ubuntu2204`, `ubuntu2404`, `ubuntu2604`, `debian12`, `debian13`, `rocky9` |

## 3. Non-negotiable tier policy

| Tier | Purpose | Deployment policy |
|---|---|---|
| **Tier 1 — Baseline** | Audit foundation and all **applicable** OS/version STIG/SRG audit requirements, identity, authentication, privilege, filesystem, MAC controls | **Mandatory** |
| **Tier 2 — Security Monitoring & IR** | CVE-independent SOC/IR monitoring: execution, credentials, persistence, security config, network and relevant cloud-host activity | **Mandatory**, with authorized waivers for justified inability to comply |
| **Tier 3 — Threat Specific** | CVE exploitation sensors, targeted investigations, specialized workload or hunt telemetry | **Select only when applicable or directed**; not a universal install |
| **Finalize** | Apply final audit configuration, including `-e 2` | **Last**, only after authorized preflight/loading decisions |

Minimum Security Requirement (MSR): **Tier 1 + Tier 2**. No unilateral reduction of the MSR. When a valid requirement cannot be supported, document the prerequisite, explicit N/A determination or approved **time-limited waiver**; applicable DoD STIG exceptions require the separate authorized compliance/AO process. Do not equate an enterprise waiver with a STIG waiver.

Preserve intentional `-D` (rule reset), **`-f 2`** (fail-secure; may panic), and **`-e 2`** (immutable until reboot) unless the user explicitly authorizes a policy change. A local or homelab preference for `-f 1` is **not** permission to change all profiles. Account for existing vendor/EDR audit rules that `-D` may clear.

## 3A. Audit failure mode (`-f 2`) — settled baseline policy; do not re-litigate

**Decision:** The enterprise baseline intentionally uses **`-f 2`** (audit failure mode: panic) in **Tier 1**. This is an accepted *policy design choice with an availability consequence*, **not an overlooked misplaced rule, an unaddressed audit finding, or an automatic request to change it to `-f 1`**. The purpose is fail-secure handling of critical audit failures where the approved baseline requires it. This is distinct from a claim that the risk is suitable for every workload without an applicability/approval review.

**Canonical location and order (v0.16.2):**

- `tier-1-baseline/00-audit-foundation.rules` contains `-D`, `-b 8192`, and `--backlog_wait_time 60000`, plus a **comment** directing maintainers to the failure mode.
- `tier-1-baseline/18-security-critical.rules` contains the single active **`-f 2`** directive for the selected profile, alongside `--loginuid-immutable`. **It is not a Tier 2 rule.**
- `finalize/99-finalize.rules` contains `-e 2` and must be applied last. **`-f 2` and `-e 2` are different controls** and must never be conflated.
- Do not move, duplicate, remove, downgrade, or silently override `-f 2` when doing routine cleanup, STIG mapping, OS-specific work, or responding to repeated third-party review comments. Keep its Tier 1 location and foundation cross-reference unless explicitly instructed to change the enterprise policy.

**Risk and exception handling:** `-f 2` can trigger a kernel panic on critical audit failures, so host availability, backlog/queue pressure, and audit-path reliability are important deployment considerations. A proposed **`-f 1`** setting (log warnings rather than panic) for a homelab, appliance, cloud image, or availability-sensitive workload is **a deviation requiring explicit, scoped approval** under the existing waiver/exception process, not a default replacement. Do not infer that an enterprise waiver alone satisfies a separate DoD STIG/AO exception requirement. State the operational impact plainly; never call `-f 2` harmless or assume performance and failure behavior were host-tested.

**Review rule:** If another reviewer repeatedly flags `-f 2` merely because it can panic, or because it is in `18-security-critical.rules` rather than `00-audit-foundation.rules`, mark it **“acknowledged, intentional Tier 1 baseline control; availability risk documented; no change authorized.”** Escalate only if the reviewer supplies a *new* specific STIG conflict, incorrect effective configuration, deployment-order defect, or an authorized waiver request. Check for exactly **one active `-f 2` per selected architecture profile**, with no unintended `-f` override later in the rule-loading order.

## 4. Tier 3 CVE naming and selection: settled decision

Every **CVE-specific** ruleset must be named **`CVE-YYYY-NNNN.rules`** (allow longer CVE number segments, e.g. `CVE-2026-109618.rules`). Each file must be independently intelligible: CVE identifier, rationale, source/detection reference, applicable OS/kernel/workload, active vs commented rules, prerequisite paths, audit keys, and how to select/retire it.

**v0.16 CVE files (each appears in all 80 variants):**

| File | Intended collection |
|---|---|
| `CVE-2026-31431.rules` | Copy Fail — AF_ALG, `splice`, execution correlation |
| `CVE-2026-43284.rules` | Dirty Frag — `splice`/`vmsplice`, execution correlation |
| `CVE-2026-43500.rules` | Dirty Frag — equivalent sensor requirement |
| `CVE-2026-74580.rules` | Failed raw-socket activity |
| `CVE-2026-109618.rules` | PHP2Shell — workload-specific application/web worker execution |
| `CVE-2026-109619.rules` | PHP2Shell — equivalent workload sensor requirement |

The general `30-exploitation.rules` remains Tier 3 and **is not renamed after a CVE**. The old generic `31-cve.rules` was removed in v0.16. Do **not** misidentify **CVE-2026-111497** as Dirty Frag: it concerns Brotli, not the kernel `splice` behavior.

**Duplicates are allowed across different CVE files** for independent asset selection, but **do not deploy duplicate equivalent rules indiscriminately**. Select one sensor implementation for shared conditions (and track all relevant CVEs), check overlap with Tier 1/2, and preserve audit keys expected by Splunk or explicitly adapt the detections. The keys `af_alg`, `splice_user`, `process_creation`, and `sock_raw_eafnosupport` are important to published examples.

**Do not state that audit rules patch a CVE.** Vendor patches or approved mitigations are the primary response; Tier 3 adds detection or interim visibility. A rule may be commented and not functional until image/workload details are supplied. The PHP2Shell service-executable candidates are **commented out in v0.16**; do not imply they are active.

## 5. CVE-agnostic Tier 2 vs hunt/Tier 3: prior decisions

**Decision standard:** Promote telemetry to Tier 2 only when it meets an **independent, enduring, broadly applicable security requirement**, and the scope/volume is defensible. A Splunk detection that appears in a CVE analytic story **does not itself justify fleet-wide auditd collection**.

| Capability | Policy decision / current status |
|---|---|
| User and root process execution | **Keep in Tier 2**; existing `execve`/`execveat` rules |
| Broad `auid=unset` / non-root service-account execution | **Not automatically Tier 2**; specifically identified through PHP2Shell; use **scoped Tier 3** or EDR/Sysmon when justified |
| `/etc/ld.so.preload` and system-wide shell config modification | **Tier 2 objective**; v0.17 activates system shell watches; absent loader-file initial creation remains an unresolved gap |
| SSH, sudoers, sensitive security config modification | Tier 1/2 objective; check existing coverage and avoid needless duplicates |
| Magic SysRq modifications | Tier 2 **candidate**; kernel/path applicability unverified |
| All users' `.bashrc`/`.profile` modifications | Tier 3 / targeted hunt, not fleet-wide baseline |
| Sudoers **read** access | Tier 3 / targeted hunt, not mandatory baseline |
| CVE-specific socket/syscall sequences, service shell behavior | Tier 3 |
| Audit event parsing and field correlation in Splunk | Mandatory **integration requirement**, not necessarily another kernel audit rule |

`29-system-config-integrity.rules` was added in v0.16 as a **commented, inactive Tier 2 proposal** for `dir=/etc perm=wa`, with conditional SysRq and narrower leaf-path alternatives. In **v0.17, only targeted system shell startup watches were activated**. The broad `/etc`, SysRq and loader leaf-path candidates **remain inactive**; do not uncomment those without explicit user approval and applicability/volume assessment. The duplicated **commented** `/etc/ld.so.preload` candidate block was removed in v0.16.1; the remaining candidate is still inactive.

### Resolved review finding — repeated `/etc/ld.so.preload` text is NOT duplicate collection

**Settled disposition (v0.16.3):** The old finding that `29-system-config-integrity.rules` contained four references to the loader preload file was **a comment-text false positive**, not duplicate rules. In v0.16.2 the path appeared on four lines (explanation plus one `# -a ...` candidate), with **zero active directives**. In v0.16.3 all 80 copies were cleaned up so that the literal path appears **exactly once**, in the single commented-out leaf-path proposal. The broad directory integrity candidate is also commented out. This cleanup **did not enable any rules**.

**Required review method:** Strip or ignore lines beginning with `#` when counting *active* audit directives; examine commented `# -a` candidates separately. Never infer duplication from a substring/reference count, which includes prose. Only reopen a duplication issue if (a) more than one equivalent active directive is actually present, (b) an unapproved candidate has been activated, or (c) another concrete functional defect is demonstrated. Otherwise report **“Resolved, explanatory comments consolidated; one inactive candidate; zero active directives; no action required.”**

**Separate open decision:** Whether to activate **broad** Tier 2 `/etc` integrity monitoring remains unresolved and requires explicit approval/volume review; targeted shell file watches were activated in v0.17; do not conflate that coverage decision with the resolved duplicate-text finding. Broad `/etc` collection is not automatically preferable to targeted watches.

**Next substantive work:** evaluate the remaining unaddressed Tier 2 loader creation, SSH/sudoers and SysRq gaps, then Tier 3 hunting candidates individually. Explain choices and collection-cost tradeoffs before altering the mandatory baseline.

## 6. OS, architecture and cloud specifics

- **Ubuntu 22.04:** Tier 1 expanded; `apparmor_parser` `/sbin` candidate and V2R10 mapping; 49/49 published rule-bearing V-IDs mapped in v0.16.4; independent official archive hash verification and host/load validation **not completed**. V-ID corrections include `useradd` V-288815, cron V-274862, finalizer V-288816. Do not claim STIG certification.
- **Ubuntu 24.04:** user-supplied V1R7 extraction: **64 source directives represented** on x86_64; does not prove live loading, exact independent current-STIG compliance or ARM64 equivalence. Some watch paths require prerequisites, notably `/var/log/sudo.log`; `/sbin/unix_update` may require checking `/usr`-merge alias.
- **Ubuntu 26.04:** inherits Ubuntu 24.04 **engineering objectives**, not 24.04 STIG authority; uses `/usr/sbin/apparmor_parser`. Check released package/image paths and new STIG applicability separately.
- **RHEL 9:** older local V2R10 reference included **81 directives**, not an independent comparison with the currently authoritative DISA publication.
- **Debian 12/13:** coverage expanded but **does not have full active Ubuntu rule-family parity**; optional `sudo`, SSH, PAM, `acl`, AppArmor, cron, and log-file paths are conditional. For **Proxmox VE**, `/etc/pve` is `pmxcfs`/FUSE: do not presume normal audit file watches establish its configuration history. Complement with PVE API/task/cluster logs.
- **Amazon Linux 2023 / 2027:** distinct AWS profiles. AL2027 was a **preview-only candidate** at the previous release review; verify current support/GA status before subsequent claims. Standard/minimal AMIs have different installed packages and SSM availability.
- **SELinux vs AppArmor:** use the applicable OS-native MAC implementation. Policy-modification auditing is separate from MAC enforcement and from AVC/denial record ingestion.
- **Architecture:** x86_64 uses b64 and where appropriate b32 compatibility ABI; ARM64 uses native b64 names, including `*at` variants where legacy syscalls are absent. Correct syscall name mapping does **not** prove identical filter semantics or STIG equivalence.
- **Cloud guests:** use provider **and OS** profile; generic noninteractive root activity does not replace exact SSM/Azure/Linux Agent/Google guest-agent watches. Those path-dependent rules are often commented pending installed-package/image verification.
- **Cloud control plane:** mandatory companion sources: **AWS CloudTrail**, **Azure Activity Log**, **GCP Cloud Audit Logs** for API, role/IAM, security-group/NSG/firewall and resource modifications; network flow logs when applicable. `auditd` cannot reconstruct remote provider API changes reliably. Cloud CLI execution != API audit trail.
- **Other sources:** prefer EDR/Sysmon for Linux for rich parent/child process context, journald/auth logs for service/authentication, and service/application logs for web or PHP behaviors when they are the better telemetry source.

## 7. Offline verification — required when making a change

We **cannot assume access to actual hosts or their logs**. Use official vendor STIGs, current package file inventories, cloud-image package manifests and documentation, distro package repositories, and ABI syscall tables. Record date, exact OS/version/architecture/image build, URL, content version/hash if available, and confidence. A repository file list proves where **a package** installs files; an image manifest supports whether a package ships on **that image build**; neither proves a runtime-created file exists.

Before distributing an update:

1. **Identify the exact scope and diff.** Compare against the latest ZIP; make only requested changes. Preserve unaffected active directives and all existing tiers.
2. **Map compliance claims.** For each STIG-derived requirement, record current product/version, V-ID, requirement, mapped rule, and whether it is active/conditional/missing/N/A. Prefer official DISA XCCDF/check text, not a copied STIG from an adjacent OS.
3. **Validate paths.** Inspect active `-w`, `-F path=`, `-F dir=` targets. Document package ownership, symlinks, optional agent paths, missing-by-default log files and approved prerequisite or waiver. Never silently remove a required watch.
4. **Check semantics.** Audit filters (`auid`, `uid`, `euid`, `success`, `exit`, `a0`...), syscall/arch interpretation, paths and recursive directory rules, relevant record types, parent-child limitations, and overlaps. Exact duplicate checks alone are insufficient.
5. **Check all profiles and ABIs.** Verify `b64`/`b32` names against appropriate x86_64/i386/AArch64 tables, do not copy b32 onto ARM64, confirm every profile has the same intended file inventory, and that Finalize is separate and last.
6. **Check keys and detection dependencies.** Do not silently rename Splunk-referenced keys. Identify whether needed `SYSCALL`, `EXECVE`, `PROCTITLE`, `PATH`, `CWD`, and event serial fields will be available and correctly parsed; their end-to-end presence **cannot be proven offline**.
7. **Assess deployment risk.** `-D`, `-f 2`, `-e 2`, missing paths, kernel syscall support, and broad `execve`, `connect`, or `dir=/etc` collection can impact system availability/throughput. Do not invent EPS or CPU performance measurements.
8. **Verify package quality.** ZIP test, rule counts, no unintended duplicates/changes, actual active vs commented directives, changelog and README claims, version headers, three docs, and scoped release report. Never mark a profile production-approved on static evidence alone.

**Known evidence limitations:** Ubuntu 24.04 matches supplied review-derived directives; Ubuntu 22.04, RHEL 9 and most other OS profiles still need independent up-to-date product-specific STIG reconciliation. No live kernel loading, event generation, audit loss/backlog, performance or Splunk forwarding validation has been performed for the 80 variants.

## 8. Primary sources to consult and keep current

- **Official DISA STIG/SRG authority:** https://www.cyber.mil/stigs/ and https://www.cyber.mil/stigs/downloads/
- **DISA releases/changes:** https://www.cyber.mil/stigs/stig-announcements
- **Linux Audit upstream:** https://github.com/linux-audit/audit-userspace (especially sample rule sources)
- **ComplianceAsCode:** https://github.com/ComplianceAsCode/content (secondary implementation/compliance comparison; may lag DISA)
- **Splunk Security Content:** https://research.splunk.com/detections/ (detection reference, **not** compliance authority)
- **Ubuntu package lists and cloud manifests:** https://packages.ubuntu.com/ ; https://cloud-images.ubuntu.com/
- **Debian package contents:** https://packages.debian.org/
- **Amazon Linux:** https://docs.aws.amazon.com/linux/
- **AWS SSM:** https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html
- **Azure Linux Agent:** https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux
- **GCP guest agent:** https://docs.cloud.google.com/compute/docs/images/manage-guest-agent
- **Proxmox:** https://pve.proxmox.com/pve-docs/

Current-release sites, versions, CVEs and requirements must be **reverified** when relevant; a prior AI answer is not an authoritative source.

## 9. Editing and communication contract for another AI

- **Do not modify files unless explicitly asked.** An assessment/review request means assessment only.
- Preserve this package's **three tiers + Finalize** and OS/provider/architecture directories. Do not collapse into common files or add mandatory new tooling.
- When asked to implement changes, state **exactly which active directives change**, which are merely comments/candidates, and which profiles are affected. Distinguish CVE threat sensors from CVE-independent SOC baseline requirements.
- **Do not fabricate STIG mapping, source hashes, CVE associations, host test results, install paths, or release approval.** Cite precise sources and note uncertainty.
- Keep the three existing docs and README in sync. **Release housekeeping completed in v0.16.1:** all 2,000 `.rules` files carry consistent v0.16.1 release metadata; 28 RHEL 9 ARM64 baseline headers are normalized; all three guide titles are current; duplicate commented preload candidates are removed; foundation comments reference the unchanged `-f 2` setting in `18-security-critical.rules`. Historical release-language remains in the README where it describes earlier work.
- **v0.16.2 follow-up:** Standardized first-line headers in the 560 Tier 2 proposal and CVE files that retained prose first lines in v0.16.1. No active directives changed.
- Previous review reports and CSV matrices may be provided as supporting evidence, but the most recent **verified ZIP** is canonical for actual active rules.
- Validate created artifacts exist before giving download paths. Prefer small, transparent diffs and a concise validation summary. If you cannot prove something without a host, label it **offline candidate / requires host validation**, not approved.

## 9B. v0.16.4 resolved recurring loader-path review comment

- In the 80 copies of `29-system-config-integrity.rules`, consolidate the prose references so `/etc/ld.so.preload` appears on **one commented candidate line** only.
- **Zero active rules were added, removed or changed** compared with v0.16.2; the candidate remains inactive. Do not file this as an unresolved duplicate based on raw text matches.
- The approved `-f 2` Tier 1 control, CVE rules, all architecture profiles, and mandatory baseline remain unchanged.

## 9A. v0.16.2 formatting-only status

- The **560** previously nonstandard first-line headers (**80** inactive `29-system-config-integrity.rules` proposals and **480** CVE-specific files) now start with the same `# TARGET ARCHITECTURE:` header format as the other rule files. Existing CVE rationale, scope, inactive/active state, audit keys, and associated comments are preserved.
- Release labels are updated to `v0.16.2` across all 2,000 rule files; the README and three guide titles are synchronized. **No active audit directives changed from v0.16.1.**
- The established `-f 2` settled policy remains unchanged; exactly one active `-f 2` and one `-e 2` remain in each of the 80 variants.
- This `AGENTS.md` remains a companion handoff outside the customer ZIP. The v0.16.2 ZIP still includes only README, three guides, and the rule tree.

## 10. Carry-forward work queue (not authorization to implement)

1. **Review remaining Tier 2 configuration-integrity gaps:** shell startup `/etc/profile`, Bash system-wide configuration and non-Debian `profile.d` now have active watches. Independently assess the initial-creation limitation of absent `/etc/ld.so.preload`, incomplete SSH/sudoers coverage on package-dependent profiles, and the conditional SysRq candidate. Broad `/etc` monitoring remains *unapproved*.
2. **Review Tier 3 non-CVE hunts separately:** user shell initialization modifications, sudoers read activity, service-scoped investigations. Never auto-promote to mandatory baseline simply because Splunk has an analytic.
3. **Review CVE file applicability and overlap:** verify vulnerability/CVE references and supported kernel/OS assumptions; consider shared collection keys and whether inactive PHP2Shell selectors actually support the intended correlation. Preserve distinct CVE filenames.
4. **Continue offline product STIG/path completeness:** authoritative Ubuntu 22.04 V2R10, RHEL, AlmaLinux, Oracle Linux, SUSE, Amazon Linux and other supported OS profiles; package/image defaults and conditional guest agents. Do not falsely claim parity/compliance.
5. **Maintain release provenance:** keep architecture/release headers, README and all three guide titles synchronized for every subsequent version. v0.16.1 fixed the previously reported housekeeping issues without changing active directives.

**If another AI receives only this file:** ask for the latest package ZIP (currently v0.16.4) before editing. The handoff contains policy and status, not the complete authoritative `.rules` content.
