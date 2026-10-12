"""PKI externa e PKI de serviços independentes; assets privados gerados fora do Git."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from common.config import SPEC, CREDENTIAL_VERSION, KEYSTORE_ALIAS

PEM = serialization.Encoding.PEM


def now():
    return datetime.now(timezone.utc)


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def spki_pin(cert):
    return base64.b64encode(hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()


def write_private(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    path.chmod(0o600)


def key():
    if SPEC['key_algorithm'] != 'RSA':
        raise ValueError('Este perfil v0.1 implementa RSA. Uma troca exige perfil/testes novos.')
    return rsa.generate_private_key(public_exponent=65537, key_size=SPEC['key_size'])


def save_key(path, value):
    write_private(path, value.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def load_cert(state, name):
    return x509.load_pem_x509_certificate((state / (name + '.crt')).read_bytes())


def ca(subject_text):
    private = key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_text)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private.public_key()), False)
            .sign(private, hashes.SHA256()))
    return private, cert


def issue(public, subject, issuer, signer, client=False, days=None, start=None, end=None):
    days = SPEC['leaf_validity_days'] if days is None else days
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer.subject).public_key(public).serial_number(x509.random_serial_number())
        .not_valid_before(start or now() - timedelta(minutes=1))
        .not_valid_after(end or min(now() + timedelta(days=days), issuer.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), False))
    if not client:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
    return builder.sign(signer, hashes.SHA256())


def android_p12(private, cert, issuer, password):
    # Perfil de compatibilidade validado no lab anterior com Android 10.
    # PBESv1 é legado: não representa proteção contra extração estática do APK.
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
                  .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                  .hmac_hash(hashes.SHA1()).build(password.encode()))
    return pkcs12.serialize_key_and_certificates(CREDENTIAL_VERSION.encode(), private, cert, [issuer], encryption)


def initialize(state):
    if (state / 'ready').is_file():
        return
    if state.exists():
        raise RuntimeError('Estado incompleto; preserve-o e investigue antes de recriar a PKI.')
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=state.parent, prefix='embedded-init-') as temp:
        folder = Path(temp) / 'state'
        folder.mkdir(mode=0o700)
        external_key, external_ca = ca('Embedded Lab External CA')
        internal_key, internal_ca = ca('Embedded Lab Internal Service CA')
        for name, private, cert in [('ca', external_key, external_ca), ('internal-ca', internal_key, internal_ca)]:
            save_key(folder / (name + '.key'), private)
            (folder / (name + '.crt')).write_bytes(cert.public_bytes(PEM))
        for name in ['server', 'backup-server', 'unpinned-server', 'shared-client', 'gateway-internal', 'backend-internal']:
            internal = name.endswith('-internal')
            client = name in {'shared-client', 'gateway-internal'}
            private = key()
            issuer, signer = (internal_ca, internal_key) if internal else (external_ca, external_key)
            subject = CREDENTIAL_VERSION if name == 'shared-client' else name if client else 'localhost'
            cert = issue(private.public_key(), subject, issuer, signer, client)
            save_key(folder / (name + '.key'), private)
            (folder / (name + '.crt')).write_bytes(cert.public_bytes(PEM))
            if name == 'shared-client':
                password = secrets.token_urlsafe(32)
                write_private(folder / 'shared-client.p12', android_p12(private, cert, issuer, password))
                write_private(folder / 'p12-password', password.encode())
                policy = {fingerprint(cert): {'version': CREDENTIAL_VERSION,
                          'serial': format(cert.serial_number, 'x'), 'enabled': True}}
                write_private(folder / 'gateway-policy.json', json.dumps(policy, indent=2).encode())
        (folder / 'ready').write_text(CREDENTIAL_VERSION + '\n')
        folder.rename(state)


def prepare_android(root, state):
    if (state / 'ready').read_text().strip() != CREDENTIAL_VERSION:
        raise RuntimeError('A geração da PKI não corresponde a credential.json; rotação exige PKI e release novos.')
    local = root / '.local'
    write_private(local / 'generated-assets/mtls/client.p12', (state / 'shared-client.p12').read_bytes())
    res = local / 'generated-res'
    (res / 'raw').mkdir(parents=True, exist_ok=True)
    (res / 'xml').mkdir(parents=True, exist_ok=True)
    (res / 'raw/lab_ca.pem').write_bytes((state / 'ca.crt').read_bytes())
    primary, backup = [spki_pin(load_cert(state, n)) for n in ['server', 'backup-server']]
    (res / 'xml/network_security_config.xml').write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="false">localhost</domain>
        <trust-anchors><certificates src="@raw/lab_ca" overridePins="false" /></trust-anchors>
        <pin-set>
            <pin digest="SHA-256">{primary}</pin>
            <pin digest="SHA-256">{backup}</pin>
        </pin-set>
    </domain-config>
</network-security-config>
''')
    # Password nunca passa na linha de comando. Arquivo gerado privado, fora do Git.
    constants = {'CREDENTIAL_VERSION': CREDENTIAL_VERSION, 'KEYSTORE_ALIAS': KEYSTORE_ALIAS,
                 'KEY_ALGORITHM': SPEC['key_algorithm'], 'EXPECTED_FINGERPRINT': fingerprint(load_cert(state, 'shared-client'))}
    lines = '\n'.join(f'    public static final String {k} = {json.dumps(v)};' for k, v in constants.items())
    password = json.dumps((state / 'p12-password').read_text())
    java = f'''package lab.mtls.embedded;
// GENERATED, PRIVATE BUILD INPUT. Not application shielding or encryption.
public final class GeneratedCredential {{
{lines}
    public static final int KEY_SIZE = {SPEC['key_size']};
    public static char[] password() {{ return {password}.toCharArray(); }}
    private GeneratedCredential() {{}}
}}
'''
    write_private(local / 'generated-java/lab/mtls/embedded/GeneratedCredential.java', java.encode())


def check(state):
    for name in ['ca', 'internal-ca', 'server', 'backup-server', 'unpinned-server',
                 'shared-client', 'gateway-internal', 'backend-internal']:
        cert = load_cert(state, name)
        if not cert.not_valid_before_utc <= now() < cert.not_valid_after_utc:
            raise RuntimeError(name + '.crt fora da validade; não desative a verificação TLS.')
