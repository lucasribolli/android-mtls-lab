"""A CA autentica a cadeia; a allowlist autoriza a geração específica."""
import json
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from common import pki
from common.http import Error


def allowed(state, fp):
    try:
        policy = json.loads((state / 'gateway-policy.json').read_text())
        entry = policy.get(fp)
    except (OSError, ValueError, AttributeError) as error:
        raise Error(503, 'Política de credencial indisponível.') from error
    if not entry or entry.get('enabled') is not True:
        raise Error(403, 'Credencial não autorizada ou geração desativada.')
    if not isinstance(entry.get('version'), str) or not isinstance(entry.get('serial'), str):
        raise Error(503, 'Política inválida.')
    return entry


def from_handshake(state, der):
    if not der:
        raise Error(403, 'Certificado cliente obrigatório.')
    cert = x509.load_der_x509_certificate(der)
    try:
        valid = (cert.not_valid_before_utc <= pki.now() < cert.not_valid_after_utc
                 and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                 and cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
                 and ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        valid = False
    if not valid:
        raise Error(403, 'Certificado sem validade/uso clientAuth esperado.')
    fp = pki.fingerprint(cert)
    entry = allowed(state, fp)
    serial = format(cert.serial_number, 'x')
    if entry['serial'] != serial:
        raise Error(403, 'Serial fora da política.')
    return {'X-Internal-MTLS-Verified': 'SUCCESS', 'X-Internal-MTLS-Fingerprint': fp,
            'X-Internal-MTLS-Serial': serial, 'X-Internal-MTLS-Version': entry['version']}
