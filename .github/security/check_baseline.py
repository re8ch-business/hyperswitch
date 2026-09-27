#!/usr/bin/env python3
"""Check copyable repository security files; GitHub settings need separate evidence."""

import argparse
import pathlib
import re
import sys

import yaml


def check(root: pathlib.Path, profile: str) -> list[str]:
    errors: list[str] = []
    policy = next((p for p in (root / "SECURITY.md", root / ".github/SECURITY.md") if p.is_file()), None)
    if policy is None or len(policy.read_text(encoding="utf-8").strip()) < 80:
        errors.append("SECURITY.md is missing or empty")

    dependabot = root / ".github/dependabot.yml"
    if not dependabot.is_file() and profile == "code":
        errors.append("code profile requires .github/dependabot.yml")
    if dependabot.is_file():
        try:
            configuration = yaml.safe_load(dependabot.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"invalid Dependabot YAML: {exc}")
            configuration = None
        if not isinstance(configuration, dict) or configuration.get("version") != 2:
            errors.append("Dependabot configuration must use version: 2")
        else:
            updates = configuration.get("updates")
            if not isinstance(updates, list) or not updates:
                errors.append("Dependabot updates must be a nonempty list")
            else:
                seen: set[tuple[str, str]] = set()
                for index, item in enumerate(updates, 1):
                    if not isinstance(item, dict):
                        errors.append(f"Dependabot update {index} must be a mapping")
                        continue
                    ecosystem = item.get("package-ecosystem")
                    directory = item.get("directory")
                    if not isinstance(ecosystem, str) or not ecosystem:
                        errors.append(f"Dependabot update {index} lacks package-ecosystem")
                    if not isinstance(directory, str) or not directory.startswith("/"):
                        errors.append(f"Dependabot update {index} needs an absolute directory")
                    if not isinstance(item.get("schedule"), dict) or not item["schedule"].get("interval"):
                        errors.append(f"Dependabot update {index} lacks schedule.interval")
                    if ecosystem == "github-actions" and directory != "/":
                        errors.append("github-actions updates must use directory: /")
                    key = (ecosystem, directory)
                    if key in seen:
                        errors.append(f"duplicate Dependabot ecosystem/directory: {key}")
                    seen.add(key)

    workflows = root / ".github/workflows"
    if not workflows.is_dir() or not list(workflows.glob("*.y*ml")):
        errors.append("at least one GitHub Actions workflow is required")
    else:
        for path in sorted(workflows.glob("*.y*ml")):
            try:
                workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                errors.append(f"{path.name}: invalid YAML: {exc}")
                continue
            if not isinstance(workflow, dict) or "permissions" not in workflow:
                errors.append(f"{path.name}: declare top-level permissions")
            for reference in re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", path.read_text(encoding="utf-8"), flags=re.MULTILINE):
                if reference.startswith("./"):
                    continue
                if reference.startswith("docker://"):
                    if "@sha256:" not in reference:
                        errors.append(f"{path.name}: pin Docker action by digest: {reference}")
                    continue
                if not re.fullmatch(r"[^@\s]+@[0-9a-fA-F]{40}", reference):
                    errors.append(f"{path.name}: pin third-party action to full commit SHA: {reference}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("code", "docs-assets"), required=True)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    errors = check(args.root, args.profile)
    if errors:
        for error in errors:
            print(f"security baseline: {error}", file=sys.stderr)
        return 1
    print(f"security baseline: local {args.profile} files passed; verify organization settings separately")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
