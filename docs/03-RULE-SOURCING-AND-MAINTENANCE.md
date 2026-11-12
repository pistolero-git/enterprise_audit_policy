# 03 — Rule Sourcing and Maintenance | v0.16.4

## v0.16.4 — Ubuntu 22.04 V2R10 audit-rule mapping (offline)

**Scope:** The published Ubuntu 22.04 V2R10 checklist identifies **49 audit-rule-related requirements** (46 V-260604–V-260649, plus V-274862, V-288815, and V-288816). All 49 have at least one **active, V-ID-labelled implementing directive** in Tier 1 or Finalize in each of the eight Ubuntu 22.04 OS/cloud/architecture variants. `-e 2` stays in `finalize/99-finalize.rules`. x86_64 includes the required b32/b64 source patterns; ARM64 uses supported native b64 syscall equivalents rather than pretending x86 32-bit rules apply.

**Evidence limits:** Mappings were cross-checked against the **published V2R10 check/fix text** at <https://stigaview.com/products/ubuntu2204/v2r10/onepage/> and the officially announced release at <https://www.cyber.mil/stigs/stig-announcements>. The original DISA V2R10 ZIP/XCCDF **was not available for independent hash verification in this review**, so this is a *published-source rule representation check*, **not** certified official archive equivalence, host loadability, STIG compliance, or event-generation evidence. The full Ubuntu 22.04 STIG has requirements beyond these 49 audit rule entries (e.g., auditd.conf and boot-time audit enablement).

**Known implementation caveats:** The STIG's V-274862 check/fix prescribes cron directory watches; it does **not** by itself audit each command executed by cron, despite the requirement title. Several other watches depend on files or packages not guaranteed on generic images (`/var/log/sudo.log`, `/var/log/journal`, `/var/log/faillog`, `/etc/security/opasswd`, ACL/PAM/OpenSSH/cron utilities). They are represented in the rules but must not be assumed successfully deployed; resolve prerequisites or obtain an approved applicability/waiver decision. `-f 2` remains settled Tier 1 policy and is unchanged.

| V2R10 requirement | Required audit behavior | Implementing file(s) | Notes |
|---|---|---|---|
| UBTU-22-654010 / V-260604 | AppArmor parser execution | `14-mac-policy.rules` | Path prerequisite: AppArmor package/binary must exist |
| UBTU-22-654015 / V-260605 | chacl execution | `12-stig-privilege.rules` | Path prerequisite: acl package/binary must exist |
| UBTU-22-654020 / V-260606 | chage execution | `10-stig-identity.rules` | — |
| UBTU-22-654025 / V-260607 | chcon execution | `12-stig-privilege.rules` | — |
| UBTU-22-654030 / V-260608 | chfn execution | `11-stig-authentication.rules` | — |
| UBTU-22-654035 / V-260609 | chsh execution | `11-stig-authentication.rules` | — |
| UBTU-22-654040 / V-260610 | crontab execution | `11-stig-authentication.rules` | Path prerequisite: cron package/binary must exist |
| UBTU-22-654045 / V-260611 | fdisk execution | `13-stig-system.rules` | Path prerequisite: fdisk package/binary must exist |
| UBTU-22-654050 / V-260612 | gpasswd execution | `10-stig-identity.rules` | — |
| UBTU-22-654055 / V-260613 | kmod execution | `13-stig-system.rules` | Path prerequisite: kmod package and path must exist |
| UBTU-22-654060 / V-260614 | modprobe execution | `13-stig-system.rules` | Path prerequisite: kmod package and path must exist |
| UBTU-22-654065 / V-260615 | mount execution | `12-stig-privilege.rules` | — |
| UBTU-22-654070 / V-260616 | newgrp execution | `11-stig-authentication.rules` | — |
| UBTU-22-654075 / V-260617 | pam_timestamp_check execution | `11-stig-authentication.rules` | Path prerequisite: PAM helper may be absent on minimized images |
| UBTU-22-654080 / V-260618 | passwd execution | `10-stig-identity.rules` | — |
| UBTU-22-654085 / V-260619 | setfacl execution | `12-stig-privilege.rules` | — |
| UBTU-22-654090 / V-260620 | ssh-agent execution | `12-stig-privilege.rules` | Path prerequisite: OpenSSH client package must exist |
| UBTU-22-654095 / V-260621 | ssh-keysign execution | `12-stig-privilege.rules` | Path prerequisite: OpenSSH client helper may be absent |
| UBTU-22-654100 / V-260622 | su execution | `11-stig-authentication.rules` | — |
| UBTU-22-654105 / V-260623 | sudo execution | `12-stig-privilege.rules` | — |
| UBTU-22-654110 / V-260624 | sudoedit execution | `12-stig-privilege.rules` | — |
| UBTU-22-654115 / V-260625 | umount execution | `12-stig-privilege.rules` | — |
| UBTU-22-654120 / V-260626 | unix_update execution | `10-stig-identity.rules` | Path prerequisite: Check /sbin versus /usr/sbin usr-merge resolution |
| UBTU-22-654125 / V-260627 | usermod execution | `10-stig-identity.rules` | — |
| UBTU-22-654130 / V-260628 | /etc/group changes | `10-stig-identity.rules` | — |
| UBTU-22-654135 / V-260629 | /etc/gshadow changes | `10-stig-identity.rules` | — |
| UBTU-22-654140 / V-260630 | /etc/security/opasswd changes | `10-stig-identity.rules` | Path prerequisite: History file may not be initialized until PAM history is enabled |
| UBTU-22-654145 / V-260631 | /etc/passwd changes | `10-stig-identity.rules` | — |
| UBTU-22-654150 / V-260632 | /etc/shadow changes | `10-stig-identity.rules` | — |
| UBTU-22-654155 / V-260633 | chmod/fchmod/fchmodat syscalls | `12-stig-privilege.rules` | — |
| UBTU-22-654160 / V-260634 | chown/fchown/fchownat/lchown syscalls | `12-stig-privilege.rules` | — |
| UBTU-22-654165 / V-260635 | denied creat/open/openat/handle/truncate syscalls | `12-stig-privilege.rules` | — |
| UBTU-22-654170 / V-260636 | delete_module syscall | `13-stig-system.rules` | — |
| UBTU-22-654175 / V-260637 | init_module/finit_module syscalls | `13-stig-system.rules` | — |
| UBTU-22-654180 / V-260638 | extended-attribute syscalls | `12-stig-privilege.rules` | — |
| UBTU-22-654185 / V-260639 | unlink/rename/rmdir syscalls | `12-stig-privilege.rules` | — |
| UBTU-22-654190 / V-260640 | /var/log/journal changes | `13-stig-system.rules` | Path prerequisite: Persistent journald path may not exist by default |
| UBTU-22-654195 / V-260641 | /var/log/btmp changes | `10-stig-identity.rules` | — |
| UBTU-22-654200 / V-260642 | /var/log/wtmp changes | `10-stig-identity.rules` | — |
| UBTU-22-654205 / V-260643 | /var/run/utmp changes | `10-stig-identity.rules` | Path prerequisite: /var/run/utmp may resolve through /run; check image |
| UBTU-22-654210 / V-260644 | /var/log/faillog changes | `10-stig-identity.rules` | Path prerequisite: Legacy faillog file may not exist |
| UBTU-22-654215 / V-260645 | /var/log/lastlog changes | `10-stig-identity.rules` | — |
| UBTU-22-654220 / V-260646 | /etc/sudoers changes | `12-stig-privilege.rules` | — |
| UBTU-22-654225 / V-260647 | /etc/sudoers.d changes | `12-stig-privilege.rules` | — |
| UBTU-22-654230 / V-260648 | execve privilege-transition auditing | `12-stig-privilege.rules` | — |
| UBTU-22-654235 / V-260649 | /var/log/sudo.log changes | `11-stig-authentication.rules` | Path prerequisite: sudo file logging is not default; configure/create before watch |
| UBTU-22-654041 / V-274862 | cron configuration/spool watches (STIG literal check/fix) | `13-stig-system.rules` | STIG title mentions script execution, but prescribed watches track changes to cron directories, not executions |
| UBTU-22-654126 / V-288815 | useradd execution | `10-stig-identity.rules` | — |
| UBTU-22-654240 / V-288816 | audit policy immutability -e 2 | `99-finalize.rules` | Finalize only; do not merge into Tier 1 before other rules |


## Purpose and release rule

This is the source-of-truth **maintenance process** for the 40 Linux OS/cloud combinations and their x86_64/ARM64 variants. Do not promote a ruleset merely because it exists under the requested OS directory or passes text/syscall-table validation. Production acceptance requires current product-STIG (or approved-SRG) traceability **and** live evidence for that image, kernel, and cloud environment.

**Tier 1:** source from current applicable OS product/version STIG or approved SRG/enterprise baseline. **Tier 2:** enterprise SOC/IR requirements (execution, persistence, privilege, network and cloud-host behavior) added beyond STIG. **Tier 3:** targeted threats/CVEs, versioned with activation criteria. **Finalize:** approved immutable policy applied last.

## Authoritative and maintained feeds

### 1. DISA STIG/SRG (authoritative product requirements)

- Released product STIG files: <https://www.cyber.mil/stigs/downloads/>
- STIG announcements, update/sunset status: <https://www.cyber.mil/stigs/stig-announcements>
- SCAP/automation downloads: <https://www.cyber.mil/stigs/SCAP/>

For **every distinct OS product and major version**, download the current STIG (XCCDF/check/fix, and applicable SCAP). Extract *all* audit-related requirements, including auditd configuration, MAC-denial forwarding and audit privilege/file watches. Verify whether 32-bit syscall rules are applicable on x86_64 and whether the corresponding ARM64 guidance differs. Document each V-ID, requirement, rule, path prerequisite, N/A rationale, and passing host evidence. This is **not** accomplished by copying one OS's rules into another OS directory.

For Debian, Rocky, AL2027 or another platform without a verified current product STIG, obtain the **applicable AO-approved SRG/organizational baseline**. Do not label a cloned RHEL or Ubuntu STIG as a published product-specific STIG for a different distribution.

### 2. Linux Audit upstream `.rules` (implementation patterns)

Repository: <https://github.com/linux-audit/audit-userspace>

Monitor its `rules/` directory, notably `10-base-config.rules`, `30-stig.rules`, `31-privileged.rules`, `99-finalize.rules`, and `README-rules`; compare upstream commits/releases. Vendor samples may be installed under `/usr/share/audit/sample-rules/` or `/usr/share/audit-rules/` depending on distro/package version. These are **examples**, not automatic product-STIG evidence.

```bash
git clone https://github.com/linux-audit/audit-userspace.git
cd audit-userspace
git fetch --all --tags
git log --oneline -- rules/
git diff <previous-reviewed-commit>..<new-commit> -- rules/
```

Auditctl field semantics and compatibility: <https://man7.org/linux/man-pages/man8/auditctl.8.html>. Its architecture guidance explicitly states syscall names/numbers can differ between x86_64, i386 and AArch64. Every `-S` rule is validated against the *target* architecture's supported table and then exercised on the target kernel. `-F path=`/`-F dir=`/`-w` depend on the presence of the actual file or directory.

### 3. ComplianceAsCode/security-content (cross-reference and remediation)

Repository: <https://github.com/ComplianceAsCode/content>

Monitor releases and changes under `linux_os/guide/system/auditing/`, `products/<product>/` profiles, `controls/` and `audit_rules_*` check/remediation definitions. Treat them as useful references to **reconcile** with the authoritative released STIG; a project merge is not itself a new requirement. Never auto-overwrite customer rules with repository changes.

```bash
git clone https://github.com/ComplianceAsCode/content.git
cd content
git fetch --all --tags
git log --oneline -- linux_os/guide/system/auditing/ products/
git diff <previous-reviewed-tag>..<new-reviewed-tag> -- linux_os/guide/system/auditing/ products/
```

### 4. Operating system and cloud vendor change feeds

| Target | Maintainer sources and subjects |
|---|---|
| RHEL 8/9/10 | <https://docs.redhat.com/>; product-specific STIG releases, audit package, SELinux, Linux kernel and privileged paths; RHEL 8 lifecycle status |
| Ubuntu 22.04/24.04/26.04 | <https://documentation.ubuntu.com/security/> and <https://documentation.ubuntu.com/release-notes/>; AppArmor changes, kernel, package paths, auditd and USG/STIG automation |
| AlmaLinux, Rocky Linux, Oracle Linux | Official vendor release/security documentation and *their own* applicable STIG/SRG (do not assume all RHEL V-IDs apply) |
| SUSE SLES15 | <https://documentation.suse.com/>; AppArmor, zypper/zypp, kernel auditing and product STIG |
| Debian 12/13 | <https://www.debian.org/doc/>; auditd, PAM/AppArmor availability, relevant approved enterprise baseline |
| Amazon Linux 2023 | <https://docs.aws.amazon.com/linux/al2023/ug/>; SELinux mode, SSM, cloud-init, kernel, DNF and corresponding AL2023 STIG |
| Amazon Linux 2027 preview | <https://docs.aws.amazon.com/linux/al2027/ug/> and <https://github.com/amazonlinux/amazon-linux-2027>; SELinux, DNF5, guest-image support and official release status |
| AWS SSM Agent | <https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html>; `/etc/amazon/ssm`, `/var/lib/amazon/ssm`, image-specific installation |
| Azure Linux Agent | <https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux>; `/etc/waagent.conf`, `/var/lib/waagent`, extension-managed modifications |
| GCP guest environment | <https://docs.cloud.google.com/compute/docs/images/manage-guest-agent>; `/etc/default/instance_configs.cfg` and `.distro`/`.template` precedence, guest-agent updates |

### 5. Cloud control-plane sources — mandatory companion telemetry

These events are **not collected by guest auditd**:

- **AWS:** <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html> — CloudTrail management operations (EC2 security groups, IAM/STS, roles, APIs), plus applicable AWS Config/VPC Flow Logs.
- **Azure:** <https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log> — Azure Activity Log for Resource Manager operations (NSG/RBAC/network resources), with identity/resource/data logs and flow logs as required.
- **GCP:** <https://docs.cloud.google.com/logging/docs/audit> — Cloud Audit Logs (Admin Activity and relevant Data Access/Policy Denied), firewall/IAM management operations; VPC Flow Logs as required.

Each cloud host's package profile must be matched to the provider account/subscription/project logging scope and forwarding route. Confirm the data exists in Splunk and supports alerting; a host audit event saying `/usr/bin/aws` or `/usr/bin/az` executed cannot prove an actual remote API call or cloud security-group change.

## v0.14 rule lineage and known limitations

| Profile | Source evidence carried in this release | What is still required |
|---|---|---|
| `ubuntu2404` x86_64 (four environments) | All 64 exact audit lines from the **user-supplied Ubuntu 24.04 V1R7 extraction**, covering 49 rule-bearing V-IDs including finalize; old source preserved | Independent check against the current official DISA package, file-path checks, live event tests and configuration-level STIG checks |
| `rhel9` x86_64 (four environments) | 81/81 active lines from the **prior locally assembled RHEL 9 V2R10 audit package** (separate artifact in the work history). Reference audit-CMP/V-ID comments added. | Verify all V-IDs against the current official STIG, exact paths installed, complete product-version requirements, and live tests |
| ARM64 variants | Platform-specific audit syscall-name translations from the corresponding x86_64 candidate. x86 b32 removed; legacy `chmod`, `rename`, `open` and others mapped to ARM-native *at calls | **Independent** ARM64 product-STIG/applicability reconciliation, missing paths, actual kernel and event tests; not automatically equivalent to x86 source lines |
| All other OS profiles | Enterprise baseline adapted to OS MAC/package family and common syscall objectives | Entire relevant product/version STIG/SRG rule-by-rule mapping and live validation; shared rule text ≠ confirmed compliance |
| AWS/Azure/GCP | Mandatory active daemon-exec, daemon-connect, noninteractive `/etc` changes; optional provider agent path candidates | Activate verified installed-agent/CLI/credential watches; confirm control-plane CloudTrail / Activity Log / Cloud Audit Logs independently |
| AL2027 | Engineering candidate based on preview documentation | GA availability, image/kernel/package validation, governing baseline/STIG and approval |

The RHEL9 source package and Ubuntu 24.04 review bundle are **previously provided work artifacts**, not verified original DISA downloads in this release. Traceability claims refer to *those saved sources*, not a full external attestation. In particular, ARM64 translated directives are *semantically different* from some exact x86 STIG fix-text lines; review their effectiveness by security objective, not string equality.

## Required maintenance cycle

1. **Inventory:** Maintain the approved operating system, version, hosting provider, architecture, image build and kernel per host population.
2. **Fetch sources:** On each official STIG revision, applicable vendor kernel/agent release, or material threat update, compare the authoritative check/fix requirements and upstream audit implementations.
3. **Map requirements:** For each V-ID/security objective, record exact `.rules` line(s), kernel ABI, file-path prerequisites, whether the OS service is installed, N/A/waiver authority, expected key/events and proof.
4. **Change in source control:** Change only the affected OS/cloud/architecture profile and its matching variants. Do not blanket-copy RHEL rules onto Ubuntu, or x86 b32 rules onto ARM64. Preserve rule sources and per-OS differences.
5. **Static checks:** Verify no duplicate exact rules, valid directive tokens, syscall names for x86_64/i386/AArch64, finalizer only last, stable keys, and all required path targets. Static success is never live success.
6. **Live tests:** Use representative disposable host image and official compliant setup; load Tier 1 and Tier 2, test event triggers and Splunk record extraction, assess `auditctl -s` loss/backlog, throughput, CPU/I/O and peak-workload performance. Activate conditional cloud agent monitors only after exact path verification. Test cloud-native management event ingestion independently.
7. **Approval and distribution:** Record versioned evidence, author/reviewer, compliance authority, exception approvals/expiry, image ID/kernel and change ticket. Promote **individual** OS/cloud/architecture profiles only after all gates pass; do not blanket-label the ZIP as STIG-compliant.
8. **Retest triggers:** New STIG, OS/major update, kernel/arch shift, AMI/image rebuild, cloud guest-agent update, control-plane logging change, or discovery of missing/duplicate/lost events.

The package deliberately contains **no** maintenance scripts, generator, per-OS catalogs or combined ruleset artifacts. Keep the upstream sync and source comparison in the maintainer's source-control workflow, not as commands customers execute in production.

## v0.14 — Official package-file evidence and guest-agent default paths

These are **sources for file paths**, not proof that the corresponding package is preinstalled on a particular AMI/VM image; inspect public image manifests separately when available. Keep version and architecture with each evidence assertion.

- Ubuntu 22.04 AppArmor package: https://packages.ubuntu.com/jammy/all/apparmor/filelist (`/sbin/apparmor_parser`)
- Ubuntu 24.04 AppArmor package: https://packages.ubuntu.com/noble/all/apparmor/filelist (`/sbin/apparmor_parser`)
- Ubuntu 26.04 AppArmor package (amd64 and arm64): https://packages.ubuntu.com/resolute/amd64/apparmor/filelist (`/usr/sbin/apparmor_parser`)
- Ubuntu 24.04 PAM binaries: https://packages.ubuntu.com/noble-updates/amd64/libpam-modules-bin/filelist (`/usr/sbin/pam_timestamp_check`, `/usr/sbin/unix_update`)
- Ubuntu 24.04 `acl`: https://packages.ubuntu.com/noble/amd64/acl/filelist (`/usr/bin/chacl`)
- Ubuntu 24.04 `openssh-client`: https://packages.ubuntu.com/noble/amd64/openssh-client/filelist (`/usr/lib/openssh/ssh-keysign`)
- Debian 12 PAM: https://packages.debian.org/bookworm/amd64/libpam-modules-bin/filelist (legacy `/sbin` path)
- Debian 13 PAM: https://packages.debian.org/trixie/amd64/libpam-modules-bin/filelist (`/usr/sbin` path)
- Debian 13 OpenSSH: https://packages.debian.org/trixie/amd64/openssh-client/filelist (`/usr/lib/openssh/ssh-keysign`)
- AWS SSM: https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html and https://docs.aws.amazon.com/systems-manager/latest/userguide/agent-install-ubuntu-64-snap.html
- Azure guest agent: https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux
- Google guest agent config and precedence: https://docs.cloud.google.com/compute/docs/images/manage-guest-agent
- Sudo defaults: https://manpages.ubuntu.com/manpages/noble/man5/sudoers.5.html
- DISA authority and current product STIG: https://www.cyber.mil/stigs/ and https://www.cyber.mil/stigs/downloads/

### Maintenance rule for package-dependent executable watches

When a STIG fix specifies a hard-coded path, distinguish the **STIG-prescribed string** from the **package's shipped path** and from `usr-merge` symlinks. Do not silently change or delete a source-derived STIG watch merely to avoid installation errors. Resolve through installed-package prerequisites or an approved interpretation/exception and record the disposition. Revalidate release upgrades, especially Ubuntu 24.04 → 26.04 and Debian 12 → 13.

### Published image package inventory — stronger than repository availability

- Canonical Ubuntu generic cloud-image `*.manifest` files (Jammy, Noble, Resolute): https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.manifest ; https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.manifest ; https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.manifest ; https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-arm64.manifest
- AWS AL2023 standard vs minimal AMI package comparison: https://docs.aws.amazon.com/linux/al2023/ug/image-comparison.html
- AWS AL2027 preview standard vs minimal AMI package comparison: https://docs.aws.amazon.com/linux/al2027/ug/AMI-minimal-and-standard-differences.html

For reproducibility, record the date/build ID (manifests are `current` and can change), whether the image is **standard vs minimal**, cloud-provider customization and CPU architecture. A listed package means included in that specific published image inventory; it does *not* prove a specific audit watch's dynamically-created file exists or that the cloud vendor's customized image matches the generic manifest.

## v0.14 — Source and traceability: Ubuntu and Debian gaps

**N1 (Ubuntu 22.04 V2R10; historical v0.14 assessment, superseded by the v0.16.4 published-source mapping above):** The former sparse profile was replaced with a broader Tier 1 candidate reflecting the Ubuntu 24.04 audit objectives but with Ubuntu 22.04 specific AppArmor parser activation (`/sbin/apparmor_parser`, V-260604). V2R10 immutability (V-288816) remains in Finalize. Obtain and preserve the original official V2R10 archive SHA256 (review references `2229b5be…` but that archive was not included in this task), extract the full audit rule-bearing V-IDs, compare all check/fix requirements, and document remaining differences. **Do not state full 49/49 verified STIG coverage.**

**N2 (Ubuntu 26.04):** The Tier 1 directives now match the Ubuntu 24.04 *engineering objectives* except for release-specific AppArmor handling and documented prerequisite assumptions. They must **not** be labeled an Ubuntu 26.04 DISA STIG baseline. Assess the exact current vendor package/image manifests and do not silently ignore missing watches.

**N3 (Debian 12/13 and Proxmox):** Added explicit user/privileged-command monitoring, login-record watches, and file-access objectives using Debian-specific path assumptions. Commands from packages not universally present (`sudo`, `acl`, PAM helpers, `openssh-client`, `cron`, AppArmor) remain commented as **conditional** requirements pending package installation or verified applicability, not automatically N/A. For Proxmox, `/etc/pve` is a `pmxcfs` FUSE filesystem; do not presume that ordinary auditd watch semantics cover its clustered configuration. Pair host audit with supported Proxmox task/API/cluster log sources.

**Acceptance rule:** These changes improve *engineering coverage* and remove the misleading parity assumption; they do not substitute for source V-ID reconciliation, image-path checks, kernel loading, event evidence or the organizational waiver process.

## v0.15 — Traceability and Debian package sources

Ubuntu 22.04 audit-rule comments now reference the V2R10 **V-IDs associated with objectives** from the current published V2R10 rule index. These comments improve traceability; they do **not** independently establish exact XCCDF fix-text equivalence. In particular: `UBTU-22-654126` / `V-288815` covers `useradd`; `UBTU-22-654041` / `V-274862` covers cron directories; and `UBTU-22-654240` / `V-288816` covers `-e 2`. The previous v0.14 labels V-288818 (useradd) and V-274870 (cron) were incorrect and replaced.

- Authoritative STIG library: https://www.cyber.mil/stigs/downloads/
- Published Ubuntu 22.04 V2R10 requirement index: https://www.stigaview.com/products/ubuntu2204/v2r10/
- Debian `kmod` package file list: https://packages.debian.org/trixie/amd64/kmod/filelist
- Debian `fdisk` package file list: https://packages.debian.org/trixie/amd64/fdisk/filelist
- Debian `apparmor` package: https://packages.debian.org/trixie/apparmor
- Proxmox release mapping/support: https://github.com/proxmox/pve-docs/blob/master/pve-faq.adoc

Rule lineage must show the **current package version** for every `.rules` file while retaining historical implementation notes. Distinguish (1) a source-mapped requirement, (2) an uncommented installed rule, (3) a successfully loaded rule, and (4) validated event generation. Only (1) and (2) can be assessed from this ZIP; (3) and (4) require running targets.

## v0.16 — CVE file provenance and classification

Each CVE-specific Tier 3 file must be named `CVE-YYYY-NNNN.rules` and include the exploit-detection intent, reference, applicable platform preconditions, enabled/conditional status, audit keys/Splunk dependency, and patch-versus-monitoring caveat. Distinguish the CVE ID from general technique names; never label a non-CVE baseline rule with a CVE solely because a detection was associated with that analytic story. Equivalent rules may occur in separate CVE files for independent selection. Do not load all of them indiscriminately: deduplicate selections explicitly, preserve required keys, and examine overlaps with Tier 1/2. New broad hunt requirements require CVE-independent justification before Tier 2 promotion.

Source detections: https://research.splunk.com/endpoint/dd16294f-44d2-40b4-a869-542c0b85113a/ (Copy Fail), https://research.splunk.com/endpoint/517e7bf8-d0aa-46ac-80e1-f9f498944b71/ (Dirty Frag), https://research.splunk.com/endpoint/7c1c36e6-014d-4a2c-b3ab-84d7cec3bbc2/ (SOCK_RAW), and https://research.splunk.com/endpoint/59a644b2-51eb-4995-9fc5-b0ff08926d73/ (PHP2Shell). Note that CVE-2026-111497 is a Brotli decoder issue, not a splice-based kernel issue.
