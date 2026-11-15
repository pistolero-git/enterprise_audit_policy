#!/usr/bin/env python3
"""Verify and expand an Enterprise Linux Audit Policy readable flat bundle.

Examples:
  python3 unpack_enterprise_audit_policy.py enterprise-audit-policy-v0.19.flat.txt --verify-only
  python3 unpack_enterprise_audit_policy.py enterprise-audit-policy-v0.19.flat.txt --output ./restored

The flat bundle is one UTF-8 readable source file. Each section has the original
relative path, exact byte length, and SHA-256. Extraction reconstructs files
byte-for-byte; no audit rules, files, or permissions are activated.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

MAGIC = b"@@AUDIT-POLICY-FLAT/1\n"
FILE_PREFIX = b"@@FILE "
END_PREFIX = b"@@END "
MAX_META_LINE = 16 * 1024


class BundleError(ValueError):
    pass


def parse_bundle(filename, include_bytes=False):
    seen = set()
    count = 0
    total = 0
    with open(filename, "rb") as source:
        if source.readline(MAX_META_LINE) != MAGIC:
            raise BundleError("Unrecognized bundle header")
        while True:
            line = source.readline(MAX_META_LINE)
            if not line:
                raise BundleError("Missing end-of-bundle record")
            if line.startswith(END_PREFIX):
                try:
                    summary = json.loads(line[len(END_PREFIX):])
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
                meta = json.loads(line[len(FILE_PREFIX):])
            except (ValueError, UnicodeDecodeError) as exc:
                raise BundleError(f"Invalid JSON metadata: {exc}") from exc
            if set(meta) != {"path", "size", "sha256"}:
                raise BundleError(f"Unexpected metadata fields near entry #{count + 1}")
            path_text, size, digest = meta["path"], meta["size"], meta["sha256"]
            if not isinstance(path_text, str) or not path_text:
                raise BundleError("Invalid path")
            rel = PurePosixPath(path_text)
            if (rel.is_absolute() or ".." in rel.parts or "." in path_text.split("/")
                    or "\\" in path_text or len(rel.parts) < 2
                    or rel.as_posix() != path_text):
                raise BundleError(f"Unsafe or noncanonical path: {path_text}")
            if path_text in seen:
                raise BundleError(f"Duplicate path: {path_text}")
            if type(size) is not int or size < 0 or size > 100_000_000:
                raise BundleError(f"Unsupported file size: {path_text}")
            if not isinstance(digest, str) or len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
                raise BundleError(f"Invalid SHA-256 field: {path_text}")
            payload = source.read(size)
            if len(payload) != size or source.read(1) != b"\n":
                raise BundleError(f"Truncated payload or missing record separator: {path_text}")
            if hashlib.sha256(payload).hexdigest() != digest:
                raise BundleError(f"SHA-256 mismatch: {path_text}")
            seen.add(path_text)
            count += 1
            total += size
            yield path_text, (payload if include_bytes else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle", type=Path, help="Single .flat.txt file")
    parser.add_argument("--output", type=Path, default=Path("./audit-policy-extracted"),
                        help="Directory to contain restored project folder (default: ./audit-policy-extracted)")
    parser.add_argument("--verify-only", action="store_true", help="Check every file without extracting")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing existing extracted files")
    args = parser.parse_args()

    try:
        # Pass 1: verify all hashes and the footer before writing anything.
        verified_count = sum(1 for _ in parse_bundle(args.bundle))
        if args.verify_only:
            print(f"VALID: {verified_count} files verified; no files written")
            return 0

        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        written_count = 0
        for name, payload in parse_bundle(args.bundle, include_bytes=True):
            target = output.joinpath(*PurePosixPath(name).parts)
            real_target = target.resolve(strict=False)
            if not real_target.is_relative_to(output):
                raise BundleError(f"Destination escapes output directory: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb" if args.overwrite else "xb") as result:
                result.write(payload)
            written_count += 1
        print(f"EXTRACTED: {written_count} files to {output}")
        return 0
    except (BundleError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
