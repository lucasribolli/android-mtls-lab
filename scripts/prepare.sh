#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

for executable in python3 openssl keytool; do
    command -v "$executable" >/dev/null || {
        printf 'Comando ausente: %s. Veja os pré-requisitos no README.\n' "$executable" >&2
        exit 1
    }
done

python3 "$repo_dir/server/lab.py" export-client
mkdir -p "$repo_dir/android/app/src/debug/res/raw"
cp "$repo_dir/.local/certs/ca.crt" "$repo_dir/android/app/src/debug/res/raw/lab_ca.pem"

if [[ ! -f "$repo_dir/.local/debug.keystore" ]]; then
    keytool -genkeypair -keystore "$repo_dir/.local/debug.keystore" \
        -storepass android -keypass android -alias androiddebugkey -keyalg RSA \
        -keysize 2048 -validity 365 -dname 'CN=Android Debug,O=MTLS Lab,C=BR'
fi
printf 'Laboratório preparado. Credenciais em .local/; CA pública no app de depuração.\n'
