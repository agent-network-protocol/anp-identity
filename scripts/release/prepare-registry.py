#!/usr/bin/env python3
"""Prepare native release builds with the exact published ANP dependency."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LOCK = Path("scripts/release/registry-Cargo.lock")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def registry_manifest(source: str) -> tuple[str, str]:
    pattern = r'(?m)^(anp\s*=\s*\{)([^\n}]*)(\})'
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise ValueError("Expected one workspace ANP dependency")
    fields = matches[0][2]
    version = re.search(r'\bversion\s*=\s*"=(\d+\.\d+\.\d+)"', fields)
    if version is None or re.search(r'\bgit\s*=', fields):
        raise ValueError("ANP release dependency must have an exact registry version")
    fields = re.sub(r'\bpath\s*=\s*"[^"]*"\s*,?\s*', "", fields)
    fields = fields.strip().strip(",").strip()
    result = source[:matches[0].start()] + "anp = { " + fields + " }" + source[matches[0].end():]
    return result, version[1]


def verify_metadata(metadata: dict, version: str) -> None:
    packages = [package for package in metadata["packages"] if package["name"] == "anp"]
    if len(packages) != 1 or packages[0]["version"] != version or packages[0].get("source") != REGISTRY:
        raise ValueError("Native release must resolve exactly one published ANP version")


def prepare(root: Path, destination: Path, *, refresh: bool = False) -> None:
    if destination.exists():
        raise ValueError("Refusing to overwrite an existing build directory")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root).strip():
        raise ValueError("Commit tracked source changes before preparing a release")
    archive = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=root)
    destination.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            # Git archives contain only the reviewed tracked source. Reject
            # special entries as well, instead of traversing source symlinks.
            for member in source.getmembers():
                if (Path(member.name).is_absolute() or ".." in Path(member.name).parts
                        or not (member.isfile() or member.isdir())):
                    raise ValueError("Unsupported source archive entry")
            source.extractall(destination)
        manifest = destination / "Cargo.toml"
        rewritten, version = registry_manifest(manifest.read_text(encoding="utf-8"))
        manifest.write_text(rewritten, encoding="utf-8")
        cargo = os.environ.get("CARGO", "cargo")
        if refresh:
            subprocess.run([cargo, "update", "--workspace"], cwd=destination, check=True)
        else:
            shutil.copy2(root / LOCK, destination / "Cargo.lock")
        metadata = json.loads(subprocess.check_output(
            [cargo, "metadata", "--format-version", "1", "--locked"], cwd=destination,
        ))
        verify_metadata(metadata, version)
        if refresh:
            (root / LOCK).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination / "Cargo.lock", root / LOCK)
        print(f"Verified registry ANP {version}")
    except BaseException:
        shutil.rmtree(destination)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", type=Path)
    mode.add_argument("--refresh-lock", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare(ROOT, args.prepare.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="anp-identity-registry-") as temporary:
            prepare(ROOT, Path(temporary) / "source", refresh=True)


if __name__ == "__main__":
    main()
