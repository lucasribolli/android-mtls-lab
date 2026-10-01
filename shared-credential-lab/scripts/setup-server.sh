#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -x "$repo_dir/server/.venv/bin/python" ]]; then
    python3 -m venv "$repo_dir/server/.venv"
fi
"$repo_dir/server/.venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -r "$repo_dir/server/requirements.txt"
