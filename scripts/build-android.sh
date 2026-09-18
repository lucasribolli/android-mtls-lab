#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
"$repo_dir/scripts/prepare.sh"
"$repo_dir/android/gradlew" --project-dir "$repo_dir/android" --no-daemon \
    --max-workers=2 assembleDebug
printf '\nAPK: %s/android/app/build/outputs/apk/debug/app-debug.apk\n' "$repo_dir"
