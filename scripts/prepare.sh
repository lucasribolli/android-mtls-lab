#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

for executable in keytool; do
    command -v "$executable" >/dev/null || {
        printf 'Comando ausente: %s. Veja os pré-requisitos no README.\n' "$executable" >&2
        exit 1
    }
done

"$repo_dir/scripts/setup-server.sh"
"$repo_dir/server/.venv/bin/python" "$repo_dir/server/lab.py" init
mkdir -p "$repo_dir/android/app/src/debug/res/raw"
cp "$repo_dir/.local/bank/ca.crt" "$repo_dir/android/app/src/debug/res/raw/lab_ca.pem"

if [[ ! -f "$repo_dir/.local/debug.keystore" ]]; then
    keytool -genkeypair -keystore "$repo_dir/.local/debug.keystore" \
        -storepass android -keypass android -alias androiddebugkey -keyalg RSA \
        -keysize 2048 -validity 365 -dname 'CN=Android Debug,O=MTLS Lab,C=BR'
fi
"$repo_dir/server/.venv/bin/python" - "$repo_dir" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes

root = Path(sys.argv[1])
public = subprocess.run(['keytool', '-exportcert', '-keystore', str(root / '.local/debug.keystore'),
                         '-storepass', 'android', '-alias', 'androiddebugkey'],
                        check=True, capture_output=True).stdout
fingerprint = x509.load_der_x509_certificate(public).fingerprint(hashes.SHA256()).hex()
policy = root / '.local/bank/attestation-policy.json'
policy.write_text(json.dumps({'package_name': 'lab.mtls', 'min_version': 3,
                              'signing_digests': [fingerprint]}, indent=2) + '\n')
policy.chmod(0o600)
print('Política de atestação vinculada à assinatura deste APK de debug.')
PY
printf 'Laboratório preparado. Credenciais em .local/; CA pública no app de depuração.\n'
