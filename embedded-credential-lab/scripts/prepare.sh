#!/usr/bin/env bash
set -euo pipefail
umask 077
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_dir"
./scripts/setup-python.sh
.venv/bin/python -m common.manage prepare
if [[ ! -f .local/debug.keystore ]]; then
    keytool -genkeypair -keystore .local/debug.keystore -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 3650 \
        -dname 'CN=Embedded mTLS Debug,O=Lab,C=BR'
fi
if [[ -n "${ANDROID_HOME:-}" ]]; then printf 'sdk.dir=%s\n' "$ANDROID_HOME" > android/local.properties; fi
