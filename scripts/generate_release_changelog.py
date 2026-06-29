#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def run_git(args):
    return subprocess.check_output(["git", *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-ref", required=True)
    parser.add_argument("--tag-name", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        previous = run_git(["describe", "--tags", "--abbrev=0", f"{args.target_ref}^"])
        log_range = f"{previous}..{args.target_ref}"
    except subprocess.CalledProcessError:
        previous = ""
        log_range = args.target_ref

    commits = run_git(["log", "--pretty=format:- %s", log_range])
    if not commits:
        commits = "- Initial release"

    previous_text = previous if previous else "initial release"
    body = f"# Knot {args.tag_name}\n\nChanges since {previous_text}:\n\n{commits}\n"
    Path(args.output).write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
