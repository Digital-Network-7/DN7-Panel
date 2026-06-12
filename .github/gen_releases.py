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
    # Conventional-commit grouping: parse `type(scope): subject`, drop noise
    # types (chore/ci/docs/…), tag the rest, and order by importance so the
    # changelog reads cleanly.
    DROP = {"chore", "ci", "build", "docs", "style", "test", "release", "refactor", "deps", "wip"}
    TAG = {
        "feat": "Feature", "feature": "Feature", "fix": "Fix", "bugfix": "Fix",
        "perf": "Performance", "security": "Security", "sec": "Security",
        "ui": "UI", "api": "API", "i18n": "i18n",
    }
    PRIORITY = {"Feature": 0, "Fix": 1, "Performance": 2, "Security": 3, "UI": 4, "API": 5, "i18n": 6}
    import re
    items = []  # (priority, tag, subject)
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.lower().startswith("merge "):
            continue
        m = re.match(r"^([a-zA-Z][\w]*)(?:\([^)]*\))?!?:\s*(.+)$", s)
        if m:
            typ = m.group(1).lower()
            if typ in DROP:
                continue
            tag = TAG.get(typ, typ.capitalize())
            subject = m.group(2).strip()
        else:
            tag, subject = None, s  # unprefixed: keep as-is, lowest priority
        prio = PRIORITY.get(tag, 9) if tag else 10
        items.append((prio, tag, subject))
        if len(items) >= 60:
            break
    # Stable sort by priority (preserves chronological order within a group).
    items.sort(key=lambda x: x[0])
    out = []
    for _, tag, subject in items[:40]:
        out.append(f"{tag}: {subject}" if tag else subject)
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
