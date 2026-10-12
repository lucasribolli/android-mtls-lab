#!/usr/bin/env bash
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
adb_args=()
if [[ $# -gt 0 ]]; then adb_args=(-s "$1"); fi
adb "${adb_args[@]}" get-state
# O backend interno NÃO é encaminhado ao Android.
for port in 8643 8644 8645 8646; do adb "${adb_args[@]}" reverse "tcp:$port" "tcp:$port"; done
adb "${adb_args[@]}" install -r "$lab_dir/android/app/build/outputs/apk/debug/app-debug.apk"
adb "${adb_args[@]}" shell am start -n lab.mtls.embedded/.MainActivity
