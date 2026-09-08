#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use python3 if available, otherwise python
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "Error: Python is required to run build.py" >&2
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/build.py" "$@"
