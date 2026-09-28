"""Política do banco + IPC com o verificador Android oficial, executado fora do aparelho."""
import base64
import json
import logging
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from auth import Error

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / 'server/attestation-verifier/build/install/attestation-verifier/bin/attestation-verifier'
ROOT_URL = 'https://android.googleapis.com/attestation/root'
STATUS_URL = 'https://android.googleapis.com/attestation/status'
LOG = logging.getLogger('mtls-lab')


class GoogleAttestation:
    def __init__(self, state):
        self.state = state
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)

    def preflight(self):
        if not VERIFIER.is_file():
            raise RuntimeError('Compile o verificador: ./scripts/setup-attestation.sh')
        self.policy()
        try:
            # Confirma Java 21/classpath antes de run-server.sh substituir um servidor ativo.
            result = subprocess.run([str(VERIFIER)], input='{}', capture_output=True,
                                    text=True, timeout=10, check=True)
            if json.loads(result.stdout).get('ok') is not False:
                raise ValueError('Verificador aceitou entrada vazia')
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise RuntimeError('Verificador não executa. Confira JDK 21 e scripts/setup-attestation.sh.') from exc

    def policy(self):
        try:
            data = json.loads((self.state / 'attestation-policy.json').read_text())
            if (set(data) != {'package_name', 'min_version', 'signing_digests'}
                    or data['package_name'] != 'lab.mtls' or type(data['min_version']) is not int
                    or data['min_version'] < 3 or not data['signing_digests']
                    or not all(re.fullmatch('[0-9a-f]{64}', v) for v in data['signing_digests'])):
                raise ValueError('Política inválida')
            return data
        except (OSError, ValueError, TypeError):
            raise Error(503, 'Política de atestação ausente/inválida. Execute scripts/prepare.sh.')

    def fetch(self, name):
        """Raízes/status só de URLs fixas HTTPS. Cache vencido nunca permite o cadastro."""
        url = ROOT_URL if name == 'roots' else STATUS_URL
        path = self.state / ('google-' + name + '.json')
        with self.lock:
            try:
                cached = json.loads(path.read_text())
                if cached['fetched_at'] <= time.time() < cached['expires_at']:
                    return cached['data']
            except (OSError, ValueError, KeyError, TypeError):
                pass
            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    raw = response.read(512 * 1024 + 1)
                    if len(raw) > 512 * 1024 or response.status != 200 or response.geturl() != url:
                        raise ValueError('Resposta inesperada')
                    data = json.loads(raw)
                    self.validate_document(name, data)
                    header = response.headers.get('Cache-Control', '')
                    age = max(0, int(response.headers.get('Age', '0')))
                    match = re.search(r'(?:^|,)\s*max-age=(\d+)', header)
                    ttl = min(int(match[1]) if match else 300, 86400 if name == 'roots' else 3600)
                    ttl = max(0, ttl - age)
                    if 'no-store' in header or 'no-cache' in header:
                        ttl = 0
                stamp = time.time()
                temporary = path.with_suffix('.tmp')
                temporary.write_text(json.dumps({'fetched_at': stamp, 'expires_at': stamp + ttl, 'data': data}))
                temporary.chmod(0o600)
                temporary.replace(path)
                LOG.info('GOOGLE_ATUALIZADO documento=%s cache_segundos=%s', name, ttl)
                return data
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise Error(503, 'Não foi possível obter raízes/revogações atuais do Google.') from exc

    @staticmethod
    def validate_document(name, data):
        if name == 'roots':
            if not isinstance(data, list) or not 1 <= len(data) <= 12:
                raise ValueError('Raízes inválidas')
            for pem in data:
                certificate = x509.load_pem_x509_certificate(pem.encode())
                if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError('Raiz sem CA')
        else:
            if not isinstance(data, dict) or not isinstance(data.get('entries'), dict):
                raise ValueError('Lista inválida')
            for serial, entry in data['entries'].items():
                if not re.fullmatch('[0-9a-fA-F]+', serial) or not isinstance(entry, dict) or not entry.get('status'):
                    raise ValueError('Status inválido')

    def revoked(self):
        data = self.fetch('status')
        self.validate_document('status', data)
        # Rejeita REVOKED, SUSPENDED e estados desconhecidos. Nunca ignora entradas.
        return {format(int(serial, 16), 'x') for serial in data['entries']}

    def check_revocation(self, chain):
        revoked = self.revoked()
        for pem in chain:
            if format(x509.load_pem_x509_certificate(pem.encode()).serial_number, 'x') in revoked:
                raise Error(403, 'Cadeia de atestação revogada/suspensa pelo Google.')

    def verify(self, chain, challenge, public_key):
        if (not isinstance(chain, list) or not 3 <= len(chain) <= 8
                or not all(isinstance(p, str) and len(p) <= 16384 for p in chain)):
            raise Error(400, 'Envie de 3 a 8 certificados de atestação PEM, folha primeiro.')
        if not self.slots.acquire(blocking=False):
            raise Error(503, 'Verificador ocupado. Tente novamente.')
        try:
            policy = self.policy()
            roots = self.fetch('roots')
            self.validate_document('roots', roots)
            revoked = self.revoked()
            # Inclui a raiz fornecida na checagem e remove âncoras revogadas do servidor.
            # A assinatura é validada com as âncoras do servidor pelo verificador oficial.
            for pem in chain:
                if format(x509.load_pem_x509_certificate(pem.encode()).serial_number, 'x') in revoked:
                    raise Error(403, 'Cadeia de atestação revogada/suspensa pelo Google.')
            roots = [pem for pem in roots if format(
                x509.load_pem_x509_certificate(pem.encode()).serial_number, 'x') not in revoked]
            if not roots:
                raise Error(503, 'Não há raízes de atestação confiáveis disponíveis.')
            payload = {'chain': chain, 'challenge': challenge, 'roots': roots,
                       'revoked': sorted(revoked), 'packageName': policy['package_name'],
                       'minVersion': policy['min_version'], 'signingDigests': policy['signing_digests']}
            result = subprocess.run([str(VERIFIER)], input=json.dumps(payload), capture_output=True,
                                    text=True, timeout=20, check=True)
            checked = json.loads(result.stdout)
            if not checked.get('ok'):
                reason = checked.get('reason', 'UNKNOWN')
                LOG.warning('ATESTACAO_RECUSADA motivo=%s', reason)
                raise Error(403, 'Atestação recusada: ' + reason)
            expected = public_key.public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
            if base64.b64decode(checked['public_key'], validate=True) != expected:
                raise Error(403, 'Chave atestada não corresponde à chave do CSR.')
            checked.pop('public_key')
            return checked
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            raise Error(503, 'Verificador de atestação indisponível.') from exc
        finally:
            self.slots.release()
