#!/usr/bin/env bash
set -euo pipefail
umask 077
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -x "$lab_dir/.venv/bin/python" ]]; then python3 -m venv "$lab_dir/.venv"; fi
"$lab_dir/.venv/bin/python" -m pip install --disable-pip-version-check -r "$lab_dir/requirements.txt"
