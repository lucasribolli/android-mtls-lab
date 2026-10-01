#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
"$repo_dir/scripts/setup-server.sh"
"$repo_dir/server/.venv/bin/python" "$repo_dir/server/lab.py" init
if [[ ! -f "$repo_dir/.local/debug.keystore" ]]; then
    keytool -genkeypair -keystore "$repo_dir/.local/debug.keystore" \
        -storepass android -keypass android -alias androiddebugkey -keyalg RSA \
        -keysize 2048 -validity 3650 -dname 'CN=Shared mTLS Debug,O=Lab,C=BR'
fi
if [[ -n "${ANDROID_HOME:-}" ]]; then
    printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$repo_dir/android/local.properties"
fi
printf 'Preparado. RASP simulado configurável com: server/.venv/bin/python server/lab.py rasp approved\n'
