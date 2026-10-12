#!/usr/bin/env bash
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
"$lab_dir/scripts/prepare.sh"
"$lab_dir/android/gradlew" -p "$lab_dir/android" --no-daemon --max-workers=2 assembleDebug
printf '\nAPK FUNCIONAL SEM DEXGUARD: %s/android/app/build/outputs/apk/debug/app-debug.apk\n' "$lab_dir"
