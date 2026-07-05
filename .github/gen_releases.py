#!/usr/bin/env python3
"""Generate releases.json — the panel's changelog index.

Built in CI on each release from the per-build archive snapshots in `releases/`
(one `<version>-build<N>.toml` per published build, committed alongside the bump).
The index is VERSION-keyed: one entry per version carrying that version's LATEST
build + its notes, so the panel can (a) detect the newest (version, build) to
offer as an update and (b) show "what's new" in the UI language. Each entry is
{ version, date, codename, build, notes } where `notes` is a per-language map
{ "en": "...", "zh-CN": "...", … }.

Published as a GitHub release asset (releases/latest/download/releases.json, no
api.github.com) on the Latest (newest-build) release.

Usage: gen_releases.py <output_path>
"""
import json
import os
import re
import subprocess
import sys
import tomllib


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout.strip()


def ver_key(v):
    parts = (v.lstrip("v").split(".") + ["0", "0", "0"])[:3]
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (0, 0, 0)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "releases.json"
    rel_dir = "releases"

    # One entry per version, keeping that version's HIGHEST build (+ its notes).
    by_version = {}  # version -> (build:int, entry:dict)
    names = sorted(os.listdir(rel_dir)) if os.path.isdir(rel_dir) else []
    for name in names:
        if not name.endswith(".toml"):
            continue
        path = os.path.join(rel_dir, name)
        try:
            with open(path, "rb") as f:
                d = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        version = str(d.get("version", "")).lstrip("v")
        if not re.match(r"^\d+\.\d+\.\d+$", version):
            continue
        try:
            build = int(d.get("build", 0) or 0)
        except (TypeError, ValueError):
            build = 0
        entry = {
            "version": version,
            # The archive file's own commit date == when that build shipped.
            "date": sh("git", "log", "-1", "--format=%cs", "--", path),
            "codename": d.get("codename", ""),
            "build": str(build),
            "notes": d.get("notes", {}) or {},
        }
        prev = by_version.get(version)
        if prev is None or build >= prev[0]:
            by_version[version] = (build, entry)

    entries = [e for _, e in by_version.values()]
    entries.sort(key=lambda e: ver_key(e["version"]), reverse=True)
    doc = {"product": "DN7 Panel", "releases": entries}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"wrote {out_path}: {len(entries)} version(s)")


if __name__ == "__main__":
    main()
