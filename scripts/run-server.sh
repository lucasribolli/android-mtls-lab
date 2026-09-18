#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_dir/.local"
python3 -u "$repo_dir/server/lab.py" serve "$@" 2>&1 | tee -a "$repo_dir/.local/server.log"
