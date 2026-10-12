"""Inspeção estática da build FUNCIONAL; nunca imprime senha, chave ou bytes do P12."""
import hashlib
import json
import os
import subprocess
import zipfile
from common.config import ROOT, STATE
from common.pki import write_private


def main():
    os.umask(0o077)
    apk = ROOT / 'android/app/build/outputs/apk/debug/app-debug.apk'
    original = (STATE / 'shared-client.p12').read_bytes()
    password = (STATE / 'p12-password').read_bytes()
    with zipfile.ZipFile(apk) as archive:
        extracted = archive.read('assets/mtls/client.p12')
        password_visible = any(password in archive.read(name) for name in archive.namelist() if name.endswith('.dex'))
    target = ROOT / '.local/validation/extracted-client.p12'
    write_private(target, extracted)
    # A linha de comando contém somente o caminho do arquivo privado, nunca a senha.
    parsed = subprocess.run(['openssl', 'pkcs12', '-in', str(target), '-info', '-noout',
                             '-passin', 'file:' + str(STATE / 'p12-password')], capture_output=True)
    result = {'build': 'FUNCTIONAL UNPROTECTED', 'asset_present': True,
              'asset_identical_to_original': hashlib.sha256(extracted).digest() == hashlib.sha256(original).digest(),
              'password_literal_found_in_dex': password_visible,
              'openssl_pkcs12_parse_success': parsed.returncode == 0,
              'protected_comparison': 'NOT AVAILABLE / NOT VALIDATED'}
    print(json.dumps(result, indent=2))
    write_private(ROOT / '.local/validation/static-report.json', json.dumps(result, indent=2).encode())
    if not all(result[k] for k in ['asset_present', 'asset_identical_to_original',
                                   'password_literal_found_in_dex', 'openssl_pkcs12_parse_success']):
        raise SystemExit('Resultado diferente da baseline sem proteção; inspecione sem exibir segredos.')


if __name__ == '__main__':
    main()
