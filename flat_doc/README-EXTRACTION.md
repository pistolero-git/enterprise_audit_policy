# Enterprise Linux Audit Policy — isolated test extraction

Source: `pistolero-git/enterprise_audit_policy` at commit `e2c4370fe1144a8cc1482dcd309dfa5881e2bf5e` (main, checked November 14, 2026).

`flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt` matches the GitHub file's blob SHA (`3a7eab4a52bc577217da48784c0ea99f8f56fae0`). It contains the reviewed documentation, which differs from the repository root Markdown documentation; the repository's root documents still need synchronization. This distribution does not modify the rules or any source documents.

## Python (Linux, Windows, macOS)

From the directory containing `flat_doc/`:

```bash
python3 flat_doc/unpack_enterprise_audit_policy.py flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt --verify-only
python3 flat_doc/unpack_enterprise_audit_policy.py flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt --test-dir ./audit-policy-test-output
```

## PowerShell (Windows PowerShell 5.1+, PowerShell 7+)

From the directory containing `flat_doc/`:

```powershell
.\flat_doc\unpack_enterprise_audit_policy.ps1 -Bundle .\flat_doc\enterprise-audit-policy-v0.19-github-reviewed.flat.txt -VerifyOnly
.\flat_doc\unpack_enterprise_audit_policy.ps1 -Bundle .\flat_doc\enterprise-audit-policy-v0.19-github-reviewed.flat.txt -TestDir .\audit-policy-test-output
```

Use a different `--test-dir` or `-TestDir` for additional runs, e.g. `./audit-policy-test-02`. Both scripts intentionally refuse to overwrite an existing destination. Neither deploys rules, touches `/etc/audit`, runs `augenrules`, or modifies system configuration.

## Result

```text
audit-policy-test-output/
  enterprise-audit-policy-github-reviewed/
    AGENTS.md
    README.md
    docs/
      01-IMPLEMENTATION-GUIDE.md
      02-MINIMUM-SECURITY-REQUIREMENT-AND-WAIVER.md
      03-RULE-SOURCING-AND-MAINTENANCE.md
      04-TIER-2-AND-3-RULE-REFERENCE.md
    rules/
      ... 2,000 .rules files ...
```

The exact top-level folder name is preserved from the flat bundle. To review files elsewhere, point to the chosen test output path. To test again, choose a new directory (the extractors have no overwrite mode).

Python verification and extraction were executed, SHA-256 matched all 2,006 files, and repeat extraction, corrupted hash, and path traversal checks were rejected. The PowerShell script uses the same framing, checksums, and restrictions, but was not runtime-tested because PowerShell is not available in the test container.
