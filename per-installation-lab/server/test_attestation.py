"""Cadeias sintéticas isoladas: exercitam o verificador oficial, sem bypass no servidor real."""
import base64
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
import attestation
import auth
import lab

SIGNER = 'ab' * 32
OID = ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17')


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x80 + ((size.bit_length()+7)//8)]) + size.to_bytes((size.bit_length()+7)//8, 'big')
    return (bytes([tag]) if isinstance(tag, int) else tag) + length + value


def integer(value, tag=2):
    raw = value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')
    if raw[0] & 128:
        raw = b'\0' + raw
    return der(tag, raw)


def tagged(number, value):
    parts = [number & 127]
    number >>= 7
    while number:
        parts.insert(0, (number & 127) | 128)
        number >>= 7
    return der(b'\xbf' + bytes(parts), value)


def seq(*values):
    return der(0x30, b''.join(values))


class Fixture:
    def __init__(self):
        self.keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
        self.root = self.cert('Only for tests root', self.keys[0].public_key(), self.keys[0], None, ca=True)
        self.intermediate = self.cert('Only for tests factory', self.keys[1].public_key(), self.keys[0], self.root,
                                      ca=True, serial_name=True)
        self.attester = self.cert('Only for tests TEE', self.keys[2].public_key(), self.keys[1], self.intermediate, ca=True)

    @staticmethod
    def cert(name, public, signer, issuer, ca=False, serial_name=False, extension=None, expired=False):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)] +
                            ([x509.NameAttribute(NameOID.SERIAL_NUMBER, 'test-factory')] if serial_name else []))
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject)
                   .public_key(public).serial_number(x509.random_serial_number())
                   .not_valid_before(lab.now() - timedelta(days=10))
                   .not_valid_after(lab.now() + timedelta(days=-1 if expired else 30))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True))
        if extension is not None:
            builder = builder.add_extension(x509.UnrecognizedExtension(OID, extension), False)
        return builder.sign(signer, hashes.SHA256())

    def chain(self, public, challenge, *, package='lab.mtls', signer=SIGNER, level=1, locked=True,
              boot=0, origin=0, expired_factory=False, version=3):
        app = seq(der(0x31, seq(der(4, package.encode()), integer(version))), der(0x31, der(4, bytes.fromhex(signer))))
        software = seq(tagged(709, der(4, app)))
        hardware = seq(tagged(702, integer(origin)),
                       tagged(704, seq(der(4, b'V'*32), der(1, b'\xff' if locked else b'\0'),
                                       integer(boot, 10), der(4, b'B'*32))), tagged(705, integer(100000)))
        extension = seq(integer(3), integer(level, 10), integer(4), integer(level, 10),
                        der(4, base64.b64decode(challenge)), der(4, b''), software, hardware)
        issuer = self.attester
        if expired_factory:
            issuer = self.cert('Only for tests TEE', self.keys[2].public_key(), self.keys[1], self.intermediate,
                               ca=True, expired=True)
        leaf = self.cert('Only for tests app', public, self.keys[2], issuer, extension=extension)
        return [certificate.public_bytes(lab.PEM).decode() for certificate in [leaf, issuer, self.intermediate, self.root]]


class IsolatedAttestor(attestation.GoogleAttestation):
    """Só importado por testes; raízes sintéticas nunca são selecionáveis via HTTP/CLI."""
    def __init__(self, state, fixture):
        super().__init__(state)
        self.fixture = fixture
        self.status = {'entries': {}}
        (state / 'attestation-policy.json').write_text(json.dumps({
            'package_name': 'lab.mtls', 'min_version': 3, 'signing_digests': [SIGNER]}))

    def fetch(self, name):
        return [self.fixture.root.public_bytes(lab.PEM).decode()] if name == 'roots' else self.status


class AttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not attestation.VERIFIER.is_file():
            raise RuntimeError('Execute scripts/setup-attestation.sh antes dos testes; não pulamos a verificação.')
        cls.fixture = Fixture()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.verifier = IsolatedAttestor(self.state, self.fixture)
        self.challenge = base64.b64encode(b'N'*32).decode()
        self.chain = self.fixture.chain(self.key.public_key(), self.challenge)

    def check(self, chain=None, challenge=None, public=None):
        return self.verifier.verify(chain or self.chain, challenge or self.challenge, public or self.key.public_key())

    def test_hardware_boot_and_expected_apk(self):
        result = self.check()
        self.assertEqual('TRUSTED_ENVIRONMENT', result['security_level'])
        self.assertEqual('VERIFIED', result['boot_state'])
        self.assertTrue(result['device_locked'])

    def test_bad_nonce_and_key_mismatch(self):
        for challenge, key in [(base64.b64encode(b'X'*32).decode(), None),
                               (None, self.fixture.keys[0].public_key())]:
            with self.subTest(challenge=challenge), self.assertRaises(auth.Error) as error:
                self.check(challenge=challenge, public=key)
            self.assertEqual(403, error.exception.status)

    def test_policy_refuses_software_imported_unlocked_unverified_and_wrong_apk(self):
        for options in [{'level': 0}, {'origin': 2}, {'locked': False}, {'boot': 1},
                        {'package': 'evil.app'}, {'signer': 'cd'*32}, {'version': 2}]:
            with self.subTest(options=options), self.assertRaises(auth.Error) as error:
                self.check(self.fixture.chain(self.key.public_key(), self.challenge, **options))
            self.assertEqual(403, error.exception.status)

    def test_revoked_and_suspended(self):
        serial = format(self.fixture.attester.serial_number, 'x')
        for status in ['REVOKED', 'SUSPENDED']:
            self.verifier.status = {'entries': {serial: {'status': status}}}
            with self.subTest(status=status), self.assertRaises(auth.Error) as error:
                self.check()
            self.assertEqual(403, error.exception.status)

    def test_revoked_root_is_refused(self):
        self.verifier.status = {'entries': {format(self.fixture.root.serial_number, 'x'): {'status': 'REVOKED'}}}
        with self.assertRaises(auth.Error) as error:
            self.check()
        self.assertEqual(403, error.exception.status)

    def test_appended_fake_extension_and_signature_tampering(self):
        leaf = x509.load_pem_x509_certificate(self.chain[0].encode())
        child = self.fixture.cert('forged child', self.key.public_key(), self.key, leaf,
                                  extension=leaf.extensions.get_extension_for_oid(OID).value.value)
        with self.assertRaises(auth.Error) as error:
            self.check([child.public_bytes(lab.PEM).decode()] + self.chain)
        self.assertEqual(403, error.exception.status)
        raw = leaf.public_bytes(serialization.Encoding.DER)
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
        forged = '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(raw).decode() + '\n-----END CERTIFICATE-----\n'
        with self.assertRaises(auth.Error):
            self.check([forged] + self.chain[1:])

    def test_old_factory_expiration_exception(self):
        self.assertTrue(self.check(self.fixture.chain(self.key.public_key(), self.challenge, expired_factory=True))['ok'])

    def test_google_roots_do_not_trust_synthetic_chain(self):
        roots = json.loads((lab.ROOT / '.local/keyattestation/roots.json').read_text())
        original = self.verifier.fetch
        with patch.object(self.verifier, 'fetch', side_effect=lambda name: roots if name == 'roots' else original(name)):
            with self.assertRaises(auth.Error) as error:
                self.check()
            self.assertEqual(403, error.exception.status)

    def test_expired_cache_and_offline_fail_closed(self):
        real = attestation.GoogleAttestation(self.state)
        (self.state / 'google-status.json').write_text(json.dumps({'fetched_at': 1, 'expires_at': 2,
                                                                 'data': {'entries': {}}}))
        with patch('attestation.urllib.request.urlopen', side_effect=OSError('offline')):
            with self.assertRaises(auth.Error) as error:
                real.revoked()
        self.assertEqual(503, error.exception.status)

    def test_missing_fields_in_google_status_are_refused(self):
        self.verifier.status = {'entries': {'123': {}}}
        with self.assertRaises(auth.Error) as error:
            self.check()
        self.assertEqual(503, error.exception.status)
