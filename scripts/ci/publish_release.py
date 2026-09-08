#!/usr/bin/env python3
"""
Publish GitHub Release and upload dist/ assets.

Generates changelog via git-cliff (or git log fallback), creates the release
via the GitHub API, and uploads all packaged archives and checksums from dist/.
"""

import argparse
import json
import mimetypes
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def detect_repo() -> str | None:
    """Detect repository in 'owner/repo' format."""
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    user = os.environ.get("CIRCLE_PROJECT_USERNAME")
    repo = os.environ.get("CIRCLE_PROJECT_REPONAME")
    if user and repo:
        return f"{user}/{repo}"
    try:
        url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)(?:\.git)?", url)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    except Exception:
        pass
    return None


def detect_tag() -> str | None:
    """Detect release tag from environment or git."""
    tag = os.environ.get("CIRCLE_TAG") or os.environ.get("GITHUB_REF_NAME")
    if tag:
        return tag
    try:
        tag = subprocess.check_output(
            ["git", "describe", "--tags", "--exact-match"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if tag:
            return tag
    except Exception:
        pass
    return None


def generate_notes(tag: str, cliff_config: Path) -> str:
    """Generate release notes using git-cliff, or fallback to git log."""
    if cliff_config.is_file():
        # Check if git-cliff is installed
        cliff_bin = shutil_which("git-cliff")
        if cliff_bin:
            try:
                res = subprocess.check_output(
                    [cliff_bin, "--config", str(cliff_config), "--tag", tag],
                    text=True,
                )
                if res.strip():
                    return res
            except Exception as e:
                print(f"⚠️ git-cliff failed: {e}. Using git log fallback.", file=sys.stderr)

    # Fallback to git log
    try:
        # Get previous tag
        prev_tag = subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0", f"{tag}^"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        log_range = f"{prev_tag}..{tag}"
    except Exception:
        log_range = tag

    try:
        commits = subprocess.check_output(
            ["git", "log", log_range, "--oneline", "--no-merges"],
            text=True,
        ).strip()
        return f"## What's Changed\n\n{commits}\n"
    except Exception:
        return f"Release {tag}\n"


def shutil_which(cmd: str) -> str | None:
    import shutil
    return shutil.which(cmd)


def api_request(method: str, url: str, token: str, data: bytes | None = None, content_type: str = "application/json") -> tuple[int, dict]:
    """Execute GitHub API request."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "clash-rs-release-script",
        "Content-Type": content_type,
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"error": err_body}
        return e.code, parsed


def main():
    parser = argparse.ArgumentParser(description="Publish release to GitHub")
    parser.add_argument("--tag", type=str, default=None, help="Release tag (e.g. v0.10.9)")
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"), help="Path to dist/ assets")
    parser.add_argument("--cliff-config", type=Path, default=Path(".github/cliff.toml"), help="Path to cliff.toml")
    parser.add_argument("--repo", type=str, default=None, help="Repository 'owner/repo'")
    parser.add_argument("--token", type=str, default=None, help="GitHub PAT token")
    args = parser.parse_args()

    token = args.token or os.environ.get("ADMIN_PAT") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("❌ Error: GitHub token required (ADMIN_PAT / GITHUB_TOKEN).", file=sys.stderr)
        return 1

    repo = args.repo or detect_repo()
    if not repo:
        print("❌ Error: Could not determine repository.", file=sys.stderr)
        return 1

    tag = args.tag or detect_tag()
    if not tag:
        print("❌ Error: Could not determine release tag.", file=sys.stderr)
        return 1

    if not args.dist_dir.is_dir():
        print(f"❌ Error: dist directory {args.dist_dir} does not exist.", file=sys.stderr)
        return 1

    print(f"Publishing release for {repo} tag {tag}...")
    notes = generate_notes(tag, args.cliff_config)
    is_prerelease = ("alpha" in tag.lower()) or ("beta" in tag.lower()) or ("rc" in tag.lower())

    # Check if release already exists
    get_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    status, release = api_request("GET", get_url, token)

    if status == 200:
        release_id = release["id"]
        upload_url_template = release["upload_url"]
        print(f"✓ Found existing release ID {release_id}")
    else:
        # Create release
        create_url = f"https://api.github.com/repos/{repo}/releases"
        payload = json.dumps({
            "tag_name": tag,
            "name": tag,
            "body": notes,
            "draft": False,
            "prerelease": is_prerelease,
        }).encode("utf-8")
        status, release = api_request("POST", create_url, token, data=payload)
        if status not in (200, 201):
            print(f"❌ Failed to create release: {release}", file=sys.stderr)
            return 1
        release_id = release["id"]
        upload_url_template = release["upload_url"]
        print(f"✓ Created new release ID {release_id}")

    # Clean upload_url: strip '{?name,label}'
    base_upload_url = upload_url_template.split("{")[0]

    # Get list of existing assets to avoid conflicts
    assets_url = f"https://api.github.com/repos/{repo}/releases/{release_id}/assets"
    _, existing_assets = api_request("GET", assets_url, token)
    existing_map = {a["name"]: a["id"] for a in existing_assets} if isinstance(existing_assets, list) else {}

    # Find files in dist/ to upload (.tar.gz, .zip, .sha256)
    files_to_upload = [
        f for f in args.dist_dir.iterdir()
        if f.is_file() and (f.suffix in [".gz", ".zip", ".sha256"] or f.name.endswith(".tar.gz"))
    ]

    print(f"Uploading {len(files_to_upload)} asset(s) to release...")
    for file_path in sorted(files_to_upload):
        name = file_path.name
        if name in existing_map:
            print(f"Deleting existing asset '{name}' (ID: {existing_map[name]})...")
            del_url = f"https://api.github.com/repos/{repo}/releases/assets/{existing_map[name]}"
            api_request("DELETE", del_url, token)

        mime_type, _ = mimetypes.guess_type(str(file_path))
        if not mime_type:
            mime_type = "application/octet-stream"

        upload_url = f"{base_upload_url}?name={urllib.parse.quote(name)}"
        file_bytes = file_path.read_bytes()

        print(f"Uploading {name} ({len(file_bytes)} bytes)...")
        up_status, up_resp = api_request("POST", upload_url, token, data=file_bytes, content_type=mime_type)
        if up_status in (200, 201):
            print(f"✓ Uploaded {name}")
        else:
            print(f"⚠️ Failed to upload {name}: {up_resp}")

    print("\n🎉 Release publish complete!")
    return 0


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
