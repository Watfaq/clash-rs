#!/usr/bin/env python3
"""
Post or update a comment on a GitHub Pull Request.

Idempotent: If a comment containing the specified identifier already exists,
it updates that comment; otherwise, it creates a new comment.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def detect_repo() -> str | None:
    """Detect repository in 'owner/repo' format from env or git."""
    # GitHub Actions env
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]

    # CircleCI env
    user = os.environ.get("CIRCLE_PROJECT_USERNAME")
    repo = os.environ.get("CIRCLE_PROJECT_REPONAME")
    if user and repo:
        return f"{user}/{repo}"

    # Git remote fallback
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


def detect_pr_number() -> int | None:
    """Detect PR number from CircleCI or GitHub Actions environment."""
    # CircleCI PR number
    pr_num = os.environ.get("CIRCLE_PR_NUMBER")
    if pr_num and pr_num.isdigit():
        return int(pr_num)

    # CircleCI PR URL: e.g. https://github.com/owner/repo/pull/123
    pr_url = os.environ.get("CIRCLE_PULL_REQUEST")
    if pr_url:
        m = re.search(r"/pull/(\d+)", pr_url)
        if m:
            return int(m.group(1))

    # GitHub Actions ref: refs/pull/123/merge
    gh_ref = os.environ.get("GITHUB_REF")
    if gh_ref:
        m = re.search(r"refs/pull/(\d+)/", gh_ref)
        if m:
            return int(m.group(1))

    return None


def github_api_request(method: str, url: str, token: str, data: dict | None = None) -> tuple[int, dict | list]:
    """Perform a request to the GitHub REST API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "clash-rs-ci-script",
    }
    payload = None
    if data is not None:
        payload = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        print(f"GitHub API error ({e.code}): {err_body}", file=sys.stderr)
        return e.code, {}


def main():
    parser = argparse.ArgumentParser(description="Post or update comment on GitHub PR")
    parser.add_argument("--comment-file", type=Path, required=True, help="Path to markdown comment file")
    parser.add_argument("--identifier", type=str, required=True, help="Substring used to match existing comments")
    parser.add_argument("--repo", type=str, default=None, help="Repository 'owner/repo'")
    parser.add_argument("--pr", type=int, default=None, help="PR number")
    parser.add_argument("--token", type=str, default=None, help="GitHub PAT token")
    args = parser.parse_args()

    token = args.token or os.environ.get("ADMIN_PAT") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("⚠️ No GitHub token found (ADMIN_PAT / GITHUB_TOKEN). Skipping PR comment.")
        return 0

    if not args.comment_file.is_file():
        print(f"⚠️ Comment file not found: {args.comment_file}. Skipping comment.")
        return 0

    comment_body = args.comment_file.read_text(encoding="utf-8")
    if not comment_body.strip():
        print("⚠️ Comment body is empty. Skipping comment.")
        return 0

    repo = args.repo or detect_repo()
    if not repo:
        print("⚠️ Could not detect GitHub repository. Skipping PR comment.")
        return 0

    pr_number = args.pr or detect_pr_number()
    if not pr_number:
        print("ℹ️ No active pull request detected for this build. Skipping PR comment.")
        return 0

    print(f"Posting/updating comment on {repo}#{pr_number}...")

    # Fetch existing comments
    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    status, comments = github_api_request("GET", comments_url, token)
    if status != 200 or not isinstance(comments, list):
        print(f"⚠️ Failed to list PR comments (status {status}). Skipping.")
        return 0

    existing_comment_id = None
    for c in comments:
        body = c.get("body", "")
        if args.identifier in body:
            existing_comment_id = c.get("id")
            break

    if existing_comment_id:
        update_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_comment_id}"
        print(f"Updating existing comment ID: {existing_comment_id}")
        status, _ = github_api_request("PATCH", update_url, token, {"body": comment_body})
        if status == 200:
            print("✓ Comment updated successfully.")
        else:
            print(f"⚠️ Failed to update comment (status {status})")
    else:
        print("Creating new comment...")
        status, _ = github_api_request("POST", comments_url, token, {"body": comment_body})
        if status == 201:
            print("✓ Comment created successfully.")
        else:
            print(f"⚠️ Failed to create comment (status {status})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
