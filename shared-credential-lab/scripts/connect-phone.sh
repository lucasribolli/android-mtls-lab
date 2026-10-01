#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
adb_args=()
if [[ $# -gt 0 ]]; then adb_args=(-s "$1"); fi
adb "${adb_args[@]}" get-state
for port in 8543 8544 8545 8546; do adb "${adb_args[@]}" reverse "tcp:$port" "tcp:$port"; done
adb "${adb_args[@]}" install -r "$repo_dir/android/app/build/outputs/apk/debug/app-debug.apk"
adb "${adb_args[@]}" shell am start -n lab.mtls.shared/.MainActivity
