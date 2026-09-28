"""Testes de integração: TLS real, cadastro, autorização e revogação em estado temporário."""
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import lab


class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='bank-tests-')
        cls.root = Path(cls.temp.name)
        cls.state = cls.root / 'bank'
        cls.other = cls.root / 'other'
        lab.initialize(cls.state)
        lab.initialize(cls.other)
        cls.servers = [lab.Server(cls.state, 0, False), lab.Server(cls.state, 0, True)]
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
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.csr = (x509.CertificateSigningRequestBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'admin-forjado')]))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                    .sign(self.key, hashes.SHA256()).public_bytes(lab.PEM).decode())
        self.token = lab.new_token(self.state, 'conta-teste')

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
        connection = http.client.HTTPSConnection(host, port, context=context or self.context(), timeout=5)
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

    def register(self, token=None, csr=None):
        return self.call(self.enrollment, '/enroll', {'csr': csr or self.csr}, token or self.token)

    def test_enrollment_and_mtls(self):
        status, response = self.register()
        self.assertEqual(200, status)
        cert = x509.load_pem_x509_certificate(response['certificate'].encode())
        self.assertEqual(response['device_id'], cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual([ExtendedKeyUsageOID.CLIENT_AUTH], list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value))
        self.assertEqual(self.key.public_key().public_numbers(), cert.public_key().public_numbers())
        self.assertEqual('conta-teste', response['account'])
        status, body = self.call(self.api, '/account', context=self.context(response['certificate']))
        self.assertEqual(200, status)
        self.assertTrue(body['mtls'])
        self.assertEqual('conta-teste', body['account'])

    def test_invalid_and_expired_tokens(self):
        self.assertEqual(401, self.register(token='x' * 32)[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE tokens SET expires=? WHERE digest=?',
                       (time.time() - 1, lab.hashlib.sha256(self.token.encode()).hexdigest()))
        self.assertEqual(401, self.register()[0])

    def test_replay_is_idempotent_and_bound_to_csr(self):
        first = self.register()
        self.assertEqual(first, self.register())
        other_csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'outro')])).sign(self.key, hashes.SHA256())
        self.assertEqual(409, self.register(csr=other_csr.public_bytes(lab.PEM).decode())[0])

    def test_concurrent_token_consumption(self):
        second = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'outro')])).sign(self.key, hashes.SHA256())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda csr: self.register(csr=csr)[0],
                                    [self.csr, second.public_bytes(lab.PEM).decode()]))
        self.assertEqual([200, 409], sorted(results))

    def test_invalid_signature_does_not_consume_token(self):
        csr = x509.load_pem_x509_csr(self.csr.encode()).public_bytes(serialization.Encoding.DER)
        damaged = csr[:-1] + bytes([csr[-1] ^ 1])
        import base64
        pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + base64.b64encode(damaged).decode() + '\n-----END CERTIFICATE REQUEST-----\n'
        self.assertEqual(400, self.register(csr=pem)[0])
        self.assertEqual(400, self.register(csr='invalid')[0])
        self.assertEqual(200, self.register()[0])

    def test_no_identity_fails_tls(self):
        with self.assertRaises(ssl.SSLError):
            self.call(self.api, '/account')

    def test_other_ca_fails_tls(self):
        ca, key = lab.load_ca(self.other)
        certificate = lab.leaf_certificate(self.key.public_key(), 'outsider', ca, key,
                                           ExtendedKeyUsageOID.CLIENT_AUTH).public_bytes(lab.PEM).decode()
        with self.assertRaises(ssl.SSLError):
            self.call(self.api, '/account', context=self.context(certificate))

    def test_valid_chain_without_registration_is_forbidden(self):
        ca, key = lab.load_ca(self.state)
        certificate = lab.leaf_certificate(self.key.public_key(), 'outsider', ca, key,
                                           ExtendedKeyUsageOID.CLIENT_AUTH).public_bytes(lab.PEM).decode()
        self.assertEqual(403, self.call(self.api, '/account', context=self.context(certificate))[0])

    def test_revocation_applies_to_next_request(self):
        _, response = self.register()
        context = self.context(response['certificate'])
        self.assertEqual(200, self.call(self.api, '/account', context=context)[0])
        with closing(lab.database(self.state)) as db, db:
            db.execute('UPDATE devices SET active=0 WHERE id=?', (response['device_id'],))
        self.assertEqual(403, self.call(self.api, '/account', context=context)[0])
        self.assertEqual(403, self.register()[0])

    def test_wrong_server_trust_and_hostname(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.call(self.enrollment, '/enroll', context=self.context(trust=self.other))
        import socket
        with socket.create_connection(('127.0.0.1', self.enrollment)) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError) as error:
                self.context().wrap_socket(raw, server_hostname='wrong.invalid')
            self.assertEqual(62, error.exception.verify_code)

    def test_expired_client_fails_tls(self):
        ca, ca_key = lab.load_ca(self.state)
        cert = (x509.CertificateBuilder().subject_name(ca.subject).issuer_name(ca.subject)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(lab.now() - timedelta(days=2))
                .not_valid_after(lab.now() - timedelta(days=1))
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .sign(ca_key, hashes.SHA256()))
        with self.assertRaises(ssl.SSLError):
            self.call(self.api, '/account', context=self.context(cert.public_bytes(lab.PEM).decode()))

    def test_routes_and_body_limits(self):
        self.assertEqual(404, self.call(self.enrollment, '/account')[0])
        self.assertEqual(400, self.call(self.enrollment, '/enroll', {'csr': self.csr, 'account': 'admin'}, self.token)[0])
        self.assertEqual(413, self.call(self.enrollment, '/enroll', {'csr': 'x' * 17000}, self.token)[0])
        self.assertEqual(400, self.call(self.enrollment, '/enroll', {'csr': None}, self.token)[0])
        _, enrolled = self.register()
        self.assertEqual(404, self.call(self.api, '/enroll', {'csr': self.csr}, self.token,
                                       self.context(enrolled['certificate']))[0])

    def test_restart_preserves_state(self):
        first = self.register()
        lab.initialize(self.state)
        self.assertEqual(first, self.register())
        self.assertEqual({'ca.key', 'server.key'}, {p.name for p in self.state.glob('*.key')})


if __name__ == '__main__':
    unittest.main(verbosity=2)
