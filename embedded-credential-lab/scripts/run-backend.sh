#!/usr/bin/env bash
set -euo pipefail
umask 077
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_dir"
exec .venv/bin/python -u -m backend.app "$@"
