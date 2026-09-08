#!/usr/bin/env python3
"""
Automated version bump and tagging script for clash-rs.

Replaces the functionality of GitHub Actions release.yml:
1. Reads current version from root Cargo.toml
2. Computes bumped version (patch, minor, major)
3. Updates Cargo.toml and runs `cargo check` to update Cargo.lock
4. Creates git commit and tag (vX.Y.Z)
5. Pushes to git remote (if --push is passed)
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def parse_version(v_str: str) -> tuple[int, int, int]:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", v_str)
    if not m:
        raise ValueError(f"Invalid semantic version: {v_str}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def bump(major: int, minor: int, patch: int, bump_type: str) -> str:
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unknown bump type: {bump_type}")


def main():
    parser = argparse.ArgumentParser(description="Bump clash-rs workspace version")
    parser.add_argument("bump_type", choices=["patch", "minor", "major"], default="minor", nargs="?", help="Version bump type")
    parser.add_argument("--commit", action="store_true", help="Create git commit and tag")
    parser.add_argument("--push", action="store_true", help="Push commit and tag to remote")
    parser.add_argument("--remote", default="origin", help="Git remote name")
    parser.add_argument("--branch", default="master", help="Git branch to push to")
    args = parser.parse_args()

    cargo_toml_path = Path("Cargo.toml")
    if not cargo_toml_path.is_file():
        print("❌ Error: Cargo.toml not found in current directory.", file=sys.stderr)
        return 1

    content = cargo_toml_path.read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', content)
    if not m:
        print("❌ Error: Could not find version in Cargo.toml", file=sys.stderr)
        return 1

    curr_ver = m.group(1)
    major, minor, patch = parse_version(curr_ver)
    new_ver = bump(major, minor, patch, args.bump_type)
    tag_name = f"v{new_ver}"

    print(f"Bumping version: {curr_ver} -> {new_ver} ({tag_name})")

    # Replace version in Cargo.toml
    new_content = re.sub(
        r'(?m)^version\s*=\s*"[^"]+"',
        f'version = "{new_ver}"',
        content,
        count=1
    )
    cargo_toml_path.write_text(new_content, encoding="utf-8")
    print("✓ Updated Cargo.toml")

    # Also update subcrates Cargo.toml if they define explicit versions
    for sub_cargo in Path(".").glob("*/Cargo.toml"):
        sub_text = sub_cargo.read_text(encoding="utf-8")
        if re.search(r'(?m)^\[package\][\s\S]*?version\s*=\s*"[0-9]', sub_text):
            sub_new = re.sub(
                r'(?m)^version\s*=\s*"[^"]+"',
                f'version = "{new_ver}"',
                sub_text,
                count=1
            )
            sub_cargo.write_text(sub_new, encoding="utf-8")
            print(f"✓ Updated {sub_cargo}")

    # Update Cargo.lock
    print("Updating Cargo.lock via `cargo check`...")
    subprocess.run(["cargo", "check", "--workspace", "--quiet"], check=False)

    if args.commit:
        # Configure git if in CI
        if not os.environ.get("GIT_AUTHOR_NAME"):
            subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=False)
            subprocess.run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"], check=False)

        # Stage modified files
        subprocess.run(["git", "add", "Cargo.toml", "Cargo.lock", "*/Cargo.toml"], check=True)
        commit_msg = f"chore: bump version to {tag_name}"
        subprocess.run(["git", "commit", "-m", commit_msg], check=True)
        print(f"✓ Created commit: {commit_msg}")

        subprocess.run(["git", "tag", tag_name], check=True)
        print(f"✓ Created tag: {tag_name}")

        if args.push:
            print(f"Pushing to {args.remote} {args.branch} and {tag_name}...")
            subprocess.run(["git", "push", args.remote, args.branch], check=True)
            subprocess.run(["git", "push", args.remote, tag_name], check=True)
            print("✓ Pushed commit and tag successfully!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
