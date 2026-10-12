"""Configuração pública central da geração; nenhum segredo neste módulo."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local/embedded'
SPEC = json.loads((ROOT / 'credential.json').read_text())
CREDENTIAL_VERSION = SPEC['credential_version']
KEYSTORE_ALIAS = SPEC['keystore_alias']
INTERNAL_HEADERS = ('X-Internal-MTLS-Verified', 'X-Internal-MTLS-Fingerprint',
                    'X-Internal-MTLS-Serial', 'X-Internal-MTLS-Version')
PORTS = {'gateway': 8643, 'health': 8644, 'unpinned': 8645, 'backup': 8646, 'backend': 8650}
