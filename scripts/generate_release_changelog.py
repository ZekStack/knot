#!/usr/bin/env python3

import argparse
import re
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_DIR / "release-changelog.md"


def _run_git(args):
    completed = subprocess.run(
        ["git", *args],
        cwd=PROJECT_DIR,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return False, (completed.stderr or "").strip()
    return True, completed.stdout.strip()


def _require_git(args, error_message):
    ok, output = _run_git(args)
    if not ok:
        print(error_message)
        print(output)
        raise RuntimeError(error_message)
    return output


def _resolve_current_tag(target_ref):
    output = _require_git(
        ["tag", "--points-at", target_ref, "--list", "v*", "--sort=-v:refname"],
        f"[release_changelog] failed to resolve tags for ref '{target_ref}'",
    )
    tags = [line.strip() for line in output.splitlines() if line.strip()]
    return tags[0] if tags else ""


def _resolve_previous_tag(target_ref):
    ok, output = _run_git(
        ["describe", "--tags", "--abbrev=0", "--match", "v*", f"{target_ref}^"]
    )
    return output.strip() if ok else ""


def _resolve_commits(range_spec, max_commits=None):
    args = ["log", "--no-merges"]
    if max_commits is not None:
        args.append(f"--max-count={max(max_commits, 1)}")
    args.extend(["--pretty=format:%h%x09%s", range_spec])

    output = _require_git(
        args,
        "[release_changelog] failed to resolve commit log",
    )
    commits = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        commits.append((parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""))
    return commits


CONVENTIONAL_SUBJECT_RE = re.compile(
    r"^(?P<type>[a-zA-Z]+)(\([^)]+\))?!?:\s*(?P<body>.+)$"
)
FIX_SUBJECT_RE = re.compile(r"\b(fix|fixes|fixed|bug|bugs|hotfix|patch|resolve|resolved)\b")
FEATURE_SUBJECT_RE = re.compile(
    r"\b(feat|feature|features|add|adds|added|implement|implemented|introduce|introduced|support|supported|improve|improved|enhance|enhanced)\b"
)


def _classify_subject(subject):
    normalized = subject.strip().lower()
    conventional_match = CONVENTIONAL_SUBJECT_RE.match(normalized)
    if conventional_match:
        commit_type = conventional_match.group("type")
        if commit_type in {"feat", "feature"}:
            return "features"
        if commit_type == "fix":
            return "fixes"

    if FIX_SUBJECT_RE.search(normalized):
        return "fixes"
    if FEATURE_SUBJECT_RE.search(normalized):
        return "features"
    return "other"


def _append_section(lines, section_title, entries):
    lines.append(f"## {section_title}")
    if not entries:
        lines.append("- none")
        lines.append("")
        return

    for short_hash, subject in entries:
        message = subject.strip() or "(no subject)"
        lines.append(f"- {message} (`{short_hash}`)")
    lines.append("")


def _render_markdown(*, display_tag, commits):
    grouped = {"features": [], "fixes": [], "other": []}
    for short_hash, subject in commits:
        grouped[_classify_subject(subject)].append((short_hash, subject))

    lines = [f"# Release Changelog: {display_tag}", ""]
    _append_section(lines, "Features", grouped["features"])
    _append_section(lines, "Fixes", grouped["fixes"])
    _append_section(lines, "Other", grouped["other"])
    return "\n".join(lines)


def _resolve_commit_limit(previous_tag, requested_max):
    if requested_max is not None:
        return max(requested_max, 1)
    return 100 if previous_tag else None


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Generate release-changelog.md from git changes."
    )
    parser.add_argument("--target-ref", default="HEAD")
    parser.add_argument("--tag-name", default="")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help=(
            "Maximum non-merge commits to include. Defaults to the complete history "
            "for a first release and 100 commits when a previous release tag exists."
        ),
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    target_ref = args.target_ref.strip() or "HEAD"
    output_path = Path(args.output).resolve()

    _require_git(
        ["rev-parse", "--verify", f"{target_ref}^{{commit}}"],
        f"[release_changelog] target ref '{target_ref}' is not a valid commit",
    )

    current_tag = _resolve_current_tag(target_ref)
    display_tag = args.tag_name.strip() or current_tag or target_ref
    previous_tag = _resolve_previous_tag(target_ref)
    range_spec = f"{previous_tag}..{target_ref}" if previous_tag else target_ref
    commit_limit = _resolve_commit_limit(previous_tag, args.max_commits)
    commits = _resolve_commits(range_spec, commit_limit)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        _render_markdown(display_tag=display_tag, commits=commits),
        encoding="utf-8",
    )
    print(f"[release_changelog] wrote {output_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError:
        raise SystemExit(1)
