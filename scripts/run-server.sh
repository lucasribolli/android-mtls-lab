#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$repo_dir/server/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
    printf 'Crie o ambiente Python antes de iniciar o servidor:\n  python3 -m venv "%s/server/.venv"\n' "$repo_dir" >&2
    exit 1
fi
mkdir -p "$repo_dir/.local"
"$python_bin" -u "$repo_dir/server/lab.py" serve "$@" 2>&1 | tee -a "$repo_dir/.local/server.log"
