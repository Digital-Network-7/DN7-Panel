#!/usr/bin/env python3
"""Generate releases.json — the panel's changelog index.

Built in CI on each release. Each entry is { version, date, codename, notes }
where `notes` is a per-language map { "en": "...", "zh-CN": "...", … } read from
release.toml for the version currently being released; past versions carry an
empty map (their notes lived in their own release at the time). Published as a
GitHub release asset (releases/latest/download/releases.json, no api.github.com)
and mirrored by dn7.cn, so the panel can show "what's new" in the UI language.

Usage: gen_releases.py <output_path>   (reads NEW_VERSION from the env)
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


def date_of(ref):
    return sh("git", "log", "-1", "--format=%cs", ref)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "releases.json"
    new_version = os.environ.get("NEW_VERSION", "").strip().lstrip("v")

    with open("release.toml", "rb") as f:
        rel = tomllib.load(f)
    cur_notes = rel.get("notes", {})
    cur_codename = rel.get("codename", "")

    # Only real version tags (v<x>.<y>.<z>); build-code tags (e.g. 27G00) excluded.
    tags = [t for t in sh("git", "tag", "-l", "v[0-9]*").splitlines()
            if re.match(r"^v\d+\.\d+\.\d+$", t.strip())]
    tags.sort(key=ver_key)

    def entry(version, ref):
        cur = version == new_version
        return {
            "version": version,
            "date": date_of(ref),
            "codename": cur_codename if cur else "",
            "notes": cur_notes if cur else {},
        }

    entries = [entry(t.lstrip("v"), t) for t in tags]
    # The release in flight: its v-tag may not exist yet, so derive from HEAD.
    if new_version and new_version not in [t.lstrip("v") for t in tags]:
        entries.append(entry(new_version, "HEAD"))

    entries.sort(key=lambda e: ver_key(e["version"]), reverse=True)
    doc = {"product": "DN7 Panel", "releases": entries}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"wrote {out_path}: {len(entries)} releases")


if __name__ == "__main__":
    main()
