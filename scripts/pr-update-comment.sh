#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/pr-update-comment.sh -u <pr_url> -m <message> [-c <@mentions>]

Examples:
  scripts/pr-update-comment.sh \
    -u https://github.com/OWNER/REPO/pull/123 \
    -m "Update: fix DNS cache race" \
    -c "@alice @bob"
EOF
}

PR_URL=""
MESSAGE=""
CC=""

while getopts ":u:m:c:h" opt; do
  case "$opt" in
    u) PR_URL="$OPTARG" ;;
    m) MESSAGE="$OPTARG" ;;
    c) CC="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
    :) echo "Missing value for -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$PR_URL" || -z "$MESSAGE" ]]; then
  echo "Missing required -u or -m" >&2
  usage
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI 'gh' not found. Install: https://cli.github.com/" >&2
  exit 1
fi

BODY="$MESSAGE"
if [[ -n "$CC" ]]; then
  BODY+=$'\n\n'
  BODY+="CC: $CC"
fi

# Requires: gh auth login
# The PR URL form is supported by gh.
gh pr comment "$PR_URL" --body "$BODY"
