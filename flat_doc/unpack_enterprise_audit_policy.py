#!/usr/bin/env python3
"""Safely verify or extract the Enterprise Linux Audit Policy flat bundle.

The default destination is a NEW isolated directory, ./audit-policy-test-output/.
The original top-level project directory from the bundle is preserved inside.
No audit rules are installed or activated.

Examples:
  python3 unpack_enterprise_audit_policy_test.py flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt --verify-only
  python3 unpack_enterprise_audit_policy_test.py flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt
  python3 unpack_enterprise_audit_policy_test.py flat_doc/enterprise-audit-policy-v0.19-github-reviewed.flat.txt --test-dir ./test-run-02

The tool verifies the entire bundle before creating the destination, extracts
into a staging directory, and moves it into place only after complete success.
It refuses any existing destination (including symlinks), to protect live trees.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile

MAGIC = b"@@AUDIT-POLICY-FLAT/1\n"
FILE_PREFIX = b"@@FILE "
END_PREFIX = b"@@END "
MAX_META_LINE = 16 * 1024
MAX_FILE_SIZE = 100_000_000


class BundleError(ValueError):
    """The bundle is malformed or fails integrity checks."""


def check_relative_path(path_text: object) -> PurePosixPath:
    if not isinstance(path_text, str) or not path_text:
        raise BundleError("Invalid relative path")
    rel = PurePosixPath(path_text)
    if (
        rel.is_absolute()
        or len(rel.parts) < 2
        or any(part in ("", ".", "..") for part in path_text.split("/"))
        or "\\" in path_text
        or ":" in path_text
        or any(ord(ch) < 32 for ch in path_text)
        or rel.as_posix() != path_text
    ):
        raise BundleError(f"Unsafe or noncanonical path: {path_text!r}")
    return rel


def parse_bundle(filename: Path, *, include_bytes: bool = False):
    """Yield fully hash-verified files; verify footer after final yielded file."""
    seen = set()
    count = 0
    total = 0
    root_name = None
    with filename.open("rb") as source:
        if source.readline(MAX_META_LINE) != MAGIC:
            raise BundleError("Unrecognized bundle header")
        while True:
            line = source.readline(MAX_META_LINE)
            if not line:
                raise BundleError("Missing end-of-bundle record")
            if line.startswith(END_PREFIX):
                try:
                    summary = json.loads(line[len(END_PREFIX) :])
                except (ValueError, UnicodeDecodeError) as exc:
                    raise BundleError(f"Invalid end record: {exc}") from exc
                if summary != {"file_count": count, "total_bytes": total}:
                    raise BundleError("End record does not match file count and size")
                if source.read(1):
                    raise BundleError("Extra data after end record")
                return
            if not line.startswith(FILE_PREFIX) or not line.endswith(b"\n"):
                raise BundleError(f"Malformed file record near entry #{count + 1}")
            try:
                meta = json.loads(line[len(FILE_PREFIX) :])
            except (ValueError, UnicodeDecodeError) as exc:
                raise BundleError(f"Invalid JSON metadata: {exc}") from exc
            if not isinstance(meta, dict) or set(meta) != {"path", "size", "sha256"}:
                raise BundleError(f"Unexpected metadata fields near entry #{count + 1}")
            rel = check_relative_path(meta["path"])
            if root_name is None:
                root_name = rel.parts[0]
            elif root_name != rel.parts[0]:
                raise BundleError("Bundle contains more than one project root")
            if rel.as_posix() in seen:
                raise BundleError(f"Duplicate path: {rel}")
            size, digest = meta["size"], meta["sha256"]
            if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
                raise BundleError(f"Unsupported file size: {rel}")
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise BundleError(f"Invalid SHA-256: {rel}")
            payload = source.read(size)
            if len(payload) != size or source.read(1) != b"\n":
                raise BundleError(f"Truncated file or missing separator: {rel}")
            if hashlib.sha256(payload).hexdigest() != digest:
                raise BundleError(f"SHA-256 mismatch: {rel}")
            seen.add(rel.as_posix())
            count += 1
            total += size
            yield rel, payload if include_bytes else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle", type=Path, help="One .flat.txt input file")
    parser.add_argument(
        "--output", "--test-dir", dest="output", type=Path,
        default=Path("./audit-policy-test-output"),
        help="NEW directory for extraction (default: ./audit-policy-test-output)",
    )
    parser.add_argument("--verify-only", action="store_true", help="Verify all checksums without writing any files")
    args = parser.parse_args()

    staging = None
    try:
        source = args.bundle.resolve(strict=True)
        verified = sum(1 for _ in parse_bundle(source))
        if args.verify_only:
            print(f"VALID: {verified} files; no files written")
            return 0

        # No destructive overwrite mode: an existing path must never be touched.
        if args.output.is_symlink() or args.output.exists():
            raise BundleError(f"Destination already exists: {args.output}. Choose a new --test-dir.")
        output = args.output.resolve(strict=False)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise BundleError(f"Destination already exists: {output}")

        staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
        written = 0
        for rel, payload in parse_bundle(source, include_bytes=True):
            target = staging.joinpath(*rel.parts)
            if not target.resolve(strict=False).is_relative_to(staging.resolve()):
                raise BundleError(f"Destination escapes test directory: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(payload)
            written += 1
        if output.exists() or output.is_symlink():
            raise BundleError(f"Destination created by another process: {output}")
        staging.rename(output)
        staging = None
        print(f"EXTRACTED: {written} files to {output}")
        print("No audit rules were installed or activated.")
        return 0
    except (BundleError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
