#!/usr/bin/env python3
"""Generate releases.json — the panel's changelog index.

Built in CI on each release from the repo's git history: one entry per
`v1.1.*` tag (plus the version being released right now, derived from HEAD),
each with the commit subjects since the previous tag. Published as a GitHub
release asset (reachable via `releases/latest/download/releases.json`, no
api.github.com) and mirrored by dn7.cn, so the panel can show "what's new"
from whichever source is available.

Usage: gen_releases.py <output_path>   (reads NEW_VERSION from the env)
"""
import json
import os
import subprocess
import sys


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout.strip()


def ver_key(v):
    parts = (v.lstrip("v").split(".") + ["0", "0", "0"])[:3]
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return (0, 0, 0)


def notes_for(rev_range):
    raw = sh("git", "log", rev_range, "--no-merges", "--pretty=format:%s")
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.lower().startswith("merge "):
            continue
        out.append(s)
        if len(out) >= 40:
            break
    return out


def date_of(ref):
    return sh("git", "log", "-1", "--format=%cs", ref)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "releases.json"
    new_version = os.environ.get("NEW_VERSION", "").strip().lstrip("v")

    tags = [t for t in sh("git", "tag", "-l", "v1.1.*").splitlines() if t.strip()]
    tags.sort(key=ver_key)  # ascending

    entries = []
    # Per-tag entries: notes are commits since the previous tag.
    for i, tag in enumerate(tags):
        rng = f"{tags[i-1]}..{tag}" if i > 0 else tag
        entries.append({
            "version": tag.lstrip("v"),
            "date": date_of(tag),
            "notes": notes_for(rng),
        })

    # The release in flight: its tag doesn't exist yet, so derive it from HEAD.
    if new_version and new_version not in [t.lstrip("v") for t in tags]:
        rng = f"{tags[-1]}..HEAD" if tags else "HEAD"
        entries.append({
            "version": new_version,
            "date": date_of("HEAD"),
            "notes": notes_for(rng),
        })

    # Newest first.
    entries.sort(key=lambda e: ver_key(e["version"]), reverse=True)

    doc = {"product": "DN7 Panel", "releases": entries}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"wrote {out_path}: {len(entries)} releases")


if __name__ == "__main__":
    main()
