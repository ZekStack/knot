#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")


def properties_version(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"{path}: missing version property")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="", help="Optional release tag, such as v0.2.0")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "library.json").read_text(encoding="utf-8"))
    manifest_version = str(manifest.get("version", ""))
    arduino_version = properties_version(root / "library.properties")
    readme = (root / "README.md").read_text(encoding="utf-8")

    errors: list[str] = []

    if not SEMVER.fullmatch(manifest_version):
        errors.append(f"library.json has invalid semantic version {manifest_version!r}")

    if manifest_version != arduino_version:
        errors.append(
            f"library.json is {manifest_version}, but library.properties is {arduino_version}"
        )

    status_pattern = re.compile(
        rf"^\| Status \| `v{re.escape(manifest_version)}` API \|$",
        re.MULTILINE,
    )
    if status_pattern.search(readme) is None:
        errors.append(f"README compatibility status does not identify v{manifest_version}")

    if args.tag:
        expected_tag = f"v{manifest_version}"
        if args.tag != expected_tag:
            errors.append(f"release tag is {args.tag}, expected {expected_tag}")

    if errors:
        raise SystemExit("\n".join(errors))

    tag_suffix = f" for tag {args.tag}" if args.tag else ""
    print(f"Knot version metadata is consistent: {manifest_version}{tag_suffix}")


if __name__ == "__main__":
    main()
