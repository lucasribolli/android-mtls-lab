"""PKI local: a chave privada do cliente é criada no servidor e compartilhada."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PEM = serialization.Encoding.PEM


def now():
    return datetime.now(timezone.utc)


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def spki_pin(cert):
    der = cert.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_key(path, private):
    path.write_bytes(private.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    path.chmod(0o600)


def load_cert(state, name):
    return x509.load_pem_x509_certificate((state / (name + '.crt')).read_bytes())


def android_p12(private, cert, ca, password):
    # Compatibilidade observada no Redmi Note 8 / Android 10: o provider nativo
    # não abre o PBES2 padrão atual. Container legado, não algoritmos do TLS.
    # O envelope NÃO é a fronteira de segurança: entrega exige HTTPS com pinning.
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder()
                  .kdf_rounds(50000)
                  .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                  .hmac_hash(hashes.SHA1()).build(password.encode()))
    return pkcs12.serialize_key_and_certificates(b'shared-v1', private, cert, [ca], encryption)


def issue(public, name, ca, issuer_key, client=False, days=30):
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca.subject).public_key(public).serial_number(x509.random_serial_number())
        .not_valid_before(now() - timedelta(minutes=1))
        .not_valid_after(min(now() + timedelta(days=days), ca.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False))
    if not client:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
    return builder.sign(issuer_key, hashes.SHA256())


def initialize(state):
    if (state / 'ready').is_file():
        return
    if state.exists():
        raise RuntimeError(f'Estado incompleto em {state}; preserve-o antes de recriar.')
    state.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=state.parent, prefix='shared-init-') as temp:
        folder = Path(temp) / 'state'
        folder.mkdir(mode=0o700)
        ca_key = key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shared mTLS Lab CA')])
        ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(now() + timedelta(days=365))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
              .sign(ca_key, hashes.SHA256()))
        save_key(folder / 'ca.key', ca_key)
        (folder / 'ca.crt').write_bytes(ca.public_bytes(PEM))
        for name in ['server', 'backup-server', 'unpinned-server', 'shared-client']:
            private = key()
            client = name == 'shared-client'
            cert = issue(private.public_key(), 'shared-v1' if client else 'localhost', ca, ca_key, client)
            save_key(folder / (name + '.key'), private)
            (folder / (name + '.crt')).write_bytes(cert.public_bytes(PEM))
            if client:
                password = secrets.token_urlsafe(32)
                p12 = android_p12(private, cert, ca, password)
                (folder / 'shared-client.p12').write_bytes(p12)
                (folder / 'p12-password').write_text(password)
                (folder / 'shared-client.p12').chmod(0o600)
                (folder / 'p12-password').chmod(0o600)
        (folder / 'rasp-demo.key').write_bytes(secrets.token_bytes(32))
        (folder / 'rasp-demo.key').chmod(0o600)
        (folder / 'ready').write_text('Credencial compartilhada; RASP simulado, não produção.\n')
        folder.rename(state)


def bundle(state):
    return {'p12_base64': base64.b64encode((state / 'shared-client.p12').read_bytes()).decode(),
            'p12_password': (state / 'p12-password').read_text(),
            'certificate_fingerprint': fingerprint(load_cert(state, 'shared-client')),
            'rasp_mode': 'DEMO', 'credential_scope': 'SHARED_ALL_INSTALLATIONS'}


def prepare_android(root, state):
    raw = root / 'android/app/src/debug/res/raw'
    xml = root / 'android/app/src/debug/res/xml'
    raw.mkdir(parents=True, exist_ok=True)
    xml.mkdir(parents=True, exist_ok=True)
    (raw / 'lab_ca.pem').write_bytes((state / 'ca.crt').read_bytes())
    primary = spki_pin(load_cert(state, 'server'))
    backup = spki_pin(load_cert(state, 'backup-server'))
    # Não usar debug-overrides: seu padrão ignora os pins nas cadeias da CA de debug.
    (xml / 'network_security_config.xml').write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="false">localhost</domain>
        <trust-anchors>
            <certificates src="@raw/lab_ca" overridePins="false" />
        </trust-anchors>
        <pin-set>
            <pin digest="SHA-256">{primary}</pin>
            <pin digest="SHA-256">{backup}</pin>
        </pin-set>
    </domain-config>
</network-security-config>
''')
    (state / 'pins-public.json').write_text(json.dumps({'primary_spki_sha256': primary,
                                                       'backup_spki_sha256': backup}, indent=2))
