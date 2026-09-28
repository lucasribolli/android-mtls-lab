"""Integração HTTPS/mTLS real, login/MFA, sessão e renovação; PKI de atestação só de teste."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import json
from pathlib import Path
import ssl
import socket
from datetime import timedelta
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import auth
import lab
from test_attestation import Fixture, IsolatedAttestor


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bank-tests-')
        cls.root = Path(cls.temp.name)
        cls.state = cls.root / 'bank'
        cls.other = cls.root / 'other'
        lab.initialize(cls.state)
        lab.initialize(cls.other)
        cls.fixture = Fixture()
        cls.attestor = IsolatedAttestor(cls.state, cls.fixture)
        cls.servers = [lab.Server(cls.state, 0, mutual, cls.attestor) for mutual in [False, True]]
        cls.threads = []
        for server in cls.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)
        cls.enrollment, cls.api = [s.server_address[1] for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server, thread in zip(cls.servers, cls.threads):
            server.shutdown()
            server.server_close()
            thread.join(5)
        cls.temp.cleanup()

    def setUp(self):
        with closing(lab.database(self.state)) as db, db:
            for table in ['users', 'auth_limits', 'enrollment_grants', 'sessions', 'devices', 'client_certificates', 'renewals']:
                db.execute('DELETE FROM ' + table)
        self.attestor.status = {'entries': {}}
        self.password = 'Password-for-test-only-123'
        self.secret = auth.create_user(self.state, 'aluno', self.password)['totp_secret']
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.csr = self.make_csr(self.key)

    @staticmethod
    def make_csr(key, name='admin-forjado'):
        return (x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                .sign(key, hashes.SHA256()).public_bytes(lab.PEM).decode())

    def credentials(self, *, account='aluno', secret=None, password=None):
        with closing(lab.database(self.state)) as db:
            last = db.execute('SELECT last_counter FROM users WHERE account=?', (account,)).fetchone()[0]
        counter = max(last + 1, int(time.time() // 30) - 1)
        return {'account': account, 'password': password or self.password,
                'otp': auth.totp(secret or self.secret, counter)}

    def context(self, certificate=None, key=None, trust=None):
        context = ssl.create_default_context(cafile=(trust or self.state) / 'ca.crt')
        if certificate:
            with tempfile.TemporaryDirectory(dir=self.root) as folder:
                folder = Path(folder)
                (folder / 'cert.pem').write_text(certificate)
                lab.save_key(folder / 'key.pem', key or self.key)
                context.load_cert_chain(folder / 'cert.pem', folder / 'key.pem')
        return context

    def call(self, port, path, payload=None, token=None, context=None, host='localhost'):
        connection = http.client.HTTPSConnection(host, port, context=context or self.context(), timeout=30)
        try:
            headers = {'Content-Type': 'application/json'}
            if token is not None:
                headers['Authorization'] = 'Bearer ' + token
            connection.request('POST' if payload is not None else 'GET', path,
                               json.dumps(payload) if payload is not None else None, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def grant(self):
        status, grant = self.call(self.enrollment, '/auth/enrollment', self.credentials())
        self.assertEqual(200, status, grant)
        return grant

    def registration(self, grant=None, key=None, csr=None, **options):
        grant = grant or self.grant()
        data = {'csr': csr or self.csr, 'attestation_chain': self.fixture.chain((key or self.key).public_key(), grant['challenge'], **options)}
        return grant, data

    def enroll(self, grant=None, data=None):
        if grant is None:
            grant, data = self.registration()
        return self.call(self.enrollment, '/enroll', data, grant['enrollment_token'])

    def registered(self):
        status, enrolled = self.enroll()
        self.assertEqual(200, status, enrolled)
        return enrolled, self.context(enrolled['certificate'])

    def login(self, context, credentials=None):
        status, session = self.call(self.api, '/session', credentials or self.credentials(), context=context)
        self.assertEqual(200, status, session)
        return session['session_token']

    def test_complete_flow_and_separate_user_session(self):
        device, context = self.registered()
        self.assertNotIn('session_token', device)
        cert = x509.load_pem_x509_certificate(device['certificate'].encode())
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(device['device_id'], cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        self.assertEqual(401, self.call(self.api, '/account', context=context)[0])
        token = self.login(context)
        status, result = self.call(self.api, '/account', token=token, context=context)
        self.assertEqual(200, status)
        self.assertTrue(result['mtls'] and result['user_session'])
        self.assertEqual('aluno', result['account'])

    def test_password_totp_replay_and_rate_limit(self):
        credentials = self.credentials()
        wrong = dict(credentials, password='wrong-password')
        self.assertEqual(401, self.call(self.enrollment, '/auth/enrollment', wrong)[0])
        invalid_otp = '000000' if credentials['otp'] != '000000' else '111111'
        self.assertEqual(401, self.call(self.enrollment, '/auth/enrollment', dict(credentials, otp=invalid_otp))[0])
        self.assertEqual(400, self.call(self.enrollment, '/auth/enrollment', dict(credentials, otp='bad'))[0])
        self.assertEqual(200, self.call(self.enrollment, '/auth/enrollment', credentials)[0])
        for _ in range(5):
            self.assertEqual(401, self.call(self.enrollment, '/auth/enrollment', credentials)[0])
        self.assertEqual(429, self.call(self.enrollment, '/auth/enrollment', credentials)[0])

    def test_rfc6238_vector_and_stored_secrets(self):
        secret = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual('94287082', auth.totp(secret, 59//30, digits=8))
        raw = (self.state / 'bank.db').read_bytes()
        self.assertNotIn(self.password.encode(), raw)
        self.assertNotIn(self.secret.encode(), raw)

    def test_expired_grant_and_challenge_binding(self):
        grant, data = self.registration()
        data['attestation_chain'] = self.fixture.chain(self.key.public_key(), base64.b64encode(b'X'*32).decode())
        self.assertEqual(403, self.enroll(grant, data)[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE enrollment_grants SET expires=0')
        self.assertEqual(401, self.enroll(grant, data)[0])

    def test_idempotent_and_concurrent_enrollment(self):
        grant, data = self.registration()
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda _: self.enroll(grant, data), range(2)))
        self.assertEqual(200, replies[0][0], replies[0])
        self.assertEqual(replies[0], replies[1])
        changed = dict(data, csr=self.make_csr(self.key, 'changed'))
        self.assertEqual(409, self.enroll(grant, changed)[0])

    def test_bad_csr_signature_does_not_consume_grant(self):
        grant, data = self.registration()
        self.assertEqual(400, self.enroll(grant, dict(data, csr='bad'))[0])
        csr = x509.load_pem_x509_csr(self.csr.encode()).public_bytes(serialization.Encoding.DER)
        damaged = csr[:-1] + bytes([csr[-1] ^ 1])
        pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + base64.b64encode(damaged).decode() + '\n-----END CERTIFICATE REQUEST-----\n'
        self.assertEqual(400, self.enroll(grant, dict(data, csr=pem))[0])
        self.assertEqual(200, self.enroll(grant, data)[0])

    def test_no_client_or_foreign_ca_fails_tls(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(self.api, '/account')
        ca, ca_key = lab.load_ca(self.other)
        cert = lab.leaf_certificate(self.key.public_key(), 'foreign', ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(self.api, '/account', context=self.context(cert.public_bytes(lab.PEM).decode()))

    def test_valid_ca_but_unregistered_and_legacy_refused(self):
        ca, ca_key = lab.load_ca(self.state)
        cert = lab.leaf_certificate(self.key.public_key(), 'legacy', ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
        pem = cert.public_bytes(lab.PEM).decode()
        self.assertEqual(403, self.call(self.api, '/session', self.credentials(), context=self.context(pem))[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('INSERT INTO devices(id,account,fingerprint,certificate) VALUES (?,?,?,?)',
                       ('legacy', 'aluno', lab.fingerprint(cert), pem))
        lab.initialize(self.state)
        self.assertEqual(403, self.call(self.api, '/session', self.credentials(), context=self.context(pem))[0])

    def test_session_cannot_cross_devices_and_account(self):
        device, context = self.registered()
        token = self.login(context)
        secret = auth.create_user(self.state, 'outra', self.password)['totp_secret']
        bad = self.credentials(account='outra', secret=secret)
        self.assertEqual(401, self.call(self.api, '/session', bad, context=context)[0])
        grant, data = self.registration()
        status, second = self.enroll(grant, data)
        self.assertEqual(200, status, second)
        self.assertEqual(401, self.call(self.api, '/account', token=token, context=self.context(second['certificate']))[0])

    def test_expired_session_logout_and_revocation(self):
        device, context = self.registered()
        token = self.login(context)
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE sessions SET expires=0')
        self.assertEqual(401, self.call(self.api, '/account', token=token, context=context)[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE sessions SET expires=?', (time.time()+60,))
        self.assertEqual(200, self.call(self.api, '/logout', {}, token=token, context=context)[0])
        self.assertEqual(401, self.call(self.api, '/account', token=token, context=context)[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE sessions SET active=1')
            db.execute('UPDATE devices SET active=0')
        self.assertEqual(403, self.call(self.api, '/account', token=token, context=context)[0])

    def test_renew_requires_mtls_session_and_retries_safely(self):
        device, context = self.registered()
        self.assertEqual(404, self.call(self.enrollment, '/renew', {})[0])
        self.assertEqual(401, self.call(self.api, '/renew', {}, context=context)[0])
        token = self.login(context)
        first = self.call(self.api, '/renew', {}, token, context)
        self.assertEqual(200, first[0], first)
        self.assertEqual(first, self.call(self.api, '/renew', {}, token, context))
        renewed = first[1]['certificate']
        self.assertNotEqual(device['certificate'], renewed)
        public = x509.load_pem_x509_certificate(renewed.encode()).public_key()
        self.assertEqual(self.key.public_key().public_numbers(), public.public_numbers())
        self.assertEqual(200, self.call(self.api, '/account', token=token, context=self.context(renewed))[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE client_certificates SET accept_until=0 WHERE fingerprint=?',
                       (lab.fingerprint(x509.load_pem_x509_certificate(device['certificate'].encode())),))
        self.assertEqual(403, self.call(self.api, '/account', token=token, context=context)[0])
        self.assertEqual(200, self.call(self.api, '/account', token=token, context=self.context(renewed))[0])

    def test_renew_checks_google_revocations_and_attestation_age(self):
        _, context = self.registered()
        token = self.login(context)
        self.attestor.status = {'entries': {format(self.fixture.attester.serial_number, 'x'): {'status': 'SUSPENDED'}}}
        self.assertEqual(403, self.call(self.api, '/renew', {}, token, context)[0])
        self.attestor.status = {'entries': {}}
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE devices SET attested_at=0')
        self.assertEqual(403, self.call(self.api, '/renew', {}, token, context)[0])

    def test_wrong_server_trust_hostname_and_http_routes(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.call(self.enrollment, '/auth/enrollment', self.credentials(), context=self.context(trust=self.other))
        with socket.create_connection(('127.0.0.1', self.enrollment)) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.context().wrap_socket(raw, server_hostname='wrong.invalid')
        self.assertEqual(404, self.call(self.enrollment, '/account')[0])
        self.assertEqual(413, self.call(self.enrollment, '/enroll', {'csr': 'X' * lab.MAX_BODY})[0])
        self.assertEqual(400, self.call(self.enrollment, '/auth/enrollment', {'account': 'aluno'})[0])

    def test_expired_client_fails_tls_even_with_active_database_record(self):
        ca, ca_key = lab.load_ca(self.state)
        with patch('lab.now', return_value=lab.now() - timedelta(days=10)):
            cert = lab.leaf_certificate(self.key.public_key(), 'expired', ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
        pem = cert.public_bytes(lab.PEM).decode()
        with closing(lab.database(self.state)) as db, db:
            db.execute('INSERT INTO devices(id,account,fingerprint,certificate,attested) VALUES (?,?,?,?,1)',
                       ('expired', 'aluno', lab.fingerprint(cert), pem))
            db.execute('INSERT INTO client_certificates VALUES (?,?,?,?)',
                       (lab.fingerprint(cert), 'expired', pem, time.time()+3600))
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(self.api, '/session', self.credentials(), context=self.context(pem))

    def test_session_only_hash_persisted_and_enrollment_grant_cannot_access_account(self):
        grant, data = self.registration()
        status, device = self.enroll(grant, data)
        self.assertEqual(200, status, device)
        context = self.context(device['certificate'])
        self.assertEqual(401, self.call(self.api, '/account', token=grant['enrollment_token'], context=context)[0])
        token = self.login(context)
        with closing(lab.database(self.state)) as db:
            row = db.execute('SELECT digest FROM sessions').fetchone()
            self.assertEqual(auth.digest(token), row['digest'])
        self.assertNotIn(token.encode(), (self.state / 'bank.db').read_bytes())

    def test_google_failure_during_renewal_preserves_old_identity(self):
        device, context = self.registered()
        token = self.login(context)
        with patch.object(self.attestor, 'check_revocation', side_effect=auth.Error(503, 'offline')):
            self.assertEqual(503, self.call(self.api, '/renew', {}, token, context)[0])
        self.assertEqual(200, self.call(self.api, '/account', token=token, context=context)[0])
        with closing(lab.database(self.state)) as db:
            self.assertEqual(device['certificate'], db.execute('SELECT certificate FROM devices').fetchone()[0])
