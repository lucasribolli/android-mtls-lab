"""TLS real nas duas pernas, portas efêmeras e PKI/contas descartáveis."""
from contextlib import closing
from datetime import timedelta
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from backend import auth
from backend import app as backend
from common import pki
from common.config import CREDENTIAL_VERSION, INTERNAL_HEADERS
from common.http import Server
from gateway import app as gateway


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.state = Path(cls.temp.name) / 'state'
        pki.initialize(cls.state); backend.initialize(cls.state)
        cls.policy = (cls.state / 'gateway-policy.json').read_bytes()
        cls.fingerprint = pki.fingerprint(pki.load_cert(cls.state, 'shared-client'))
        cls.serial = format(pki.load_cert(cls.state, 'shared-client').serial_number, 'x')
        cls.servers = {}
        internal = Server(('127.0.0.1', 0), backend.context(cls.state), backend.Backend(cls.state), 'test-backend')
        cls.servers['backend'] = internal
        cls.edge = gateway.Gateway(cls.state, internal.server_port)
        cls.servers['edge'] = Server(('127.0.0.1', 0), gateway.external_context(cls.state), cls.edge, 'test-edge')
        for name, cert in [('primary', 'server'), ('backup', 'backup-server'), ('unpinned', 'unpinned-server')]:
            cls.servers[name] = Server(('127.0.0.1', 0), gateway.external_context(cls.state, cert, False), gateway.Health(name), name)
        for server in cls.servers.values():
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.make_cert('unregistered')
        cls.make_cert('expired', start=pki.now() - timedelta(days=3), end=pki.now() - timedelta(days=1))
        cls.make_cert('wrong-eku', client=False)
        cls.make_cert('untrusted', foreign=True)
        cls.make_cert('other-service', internal=True)

    @classmethod
    def make_cert(cls, name, internal=False, foreign=False, client=True, **kwargs):
        if foreign:
            signer, issuer = pki.ca('Foreign CA')
        else:
            base = 'internal-ca' if internal else 'ca'
            signer = serialization.load_pem_private_key((cls.state / (base + '.key')).read_bytes(), None)
            issuer = pki.load_cert(cls.state, base)
        private = pki.key()
        cert = pki.issue(private.public_key(), name, issuer, signer, client, **kwargs)
        pki.save_key(cls.state / (name + '.key'), private)
        (cls.state / (name + '.crt')).write_bytes(cert.public_bytes(pki.PEM))

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers.values():
            server.shutdown(); server.server_close()
        cls.temp.cleanup()

    def setUp(self):
        (self.state / 'gateway-policy.json').write_bytes(self.policy)
        with closing(auth.connect(self.state)) as db, db:
            for table in ['users', 'sessions', 'auth_limits']:
                db.execute('DELETE FROM ' + table)
        self.password = 'only-disposable-test-password'
        self.user = auth.create_user(self.state, 'alice', self.password)

    def client(self, internal=False, identity='shared-client'):
        ctx = ssl.create_default_context(cafile=self.state / ('internal-ca.crt' if internal else 'ca.crt'))
        if identity:
            ctx.load_cert_chain(self.state / (identity + '.crt'), self.state / (identity + '.key'))
        return ctx

    def call(self, path='/identity', target='edge', data=None, identity='shared-client', token=None, headers=None, ctx=None):
        conn = http.client.HTTPSConnection('localhost', self.servers[target].server_port,
                    context=ctx or self.client(target == 'backend', identity), timeout=4)
        supplied = {'Content-Type': 'application/json', **(headers or {})}
        if token is not None: supplied['Authorization'] = 'Bearer ' + token
        try:
            conn.request('POST' if data is not None else 'GET', path,
                         json.dumps(data) if data is not None else None, supplied)
            result = conn.getresponse()
            self.assertEqual(result.getheader('Cache-Control'), 'no-store')
            return result.status, json.loads(result.read())
        finally:
            conn.close()

    def credentials(self):
        return {'account': 'alice', 'password': self.password,
                'otp': auth.totp(self.user['totp_secret'], int(time.time() // 30))}

    def metadata(self):
        return dict(zip(INTERNAL_HEADERS, ['SUCCESS', self.fingerprint, self.serial, CREDENTIAL_VERSION]))

    def test_valid_shared_client_and_forwarded_metadata(self):
        status, identity = self.call()
        self.assertEqual(status, 200)
        self.assertEqual(identity['client_fingerprint'], self.fingerprint)
        self.assertEqual(identity['client_serial'], self.serial)
        self.assertEqual(identity['credential_version'], CREDENTIAL_VERSION)
        self.assertEqual(identity['internal_peer'], 'gateway-internal')
        self.assertEqual(identity['mtls_termination'], 'API_GATEWAY')
        self.assertFalse(identity['unique_device_identity'])

    def test_no_client_certificate_even_with_spoofed_headers(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(identity=None, headers={'X-Internal-MTLS-Verified': 'SUCCESS', 'X-Internal-MTLS-Fingerprint': 'fake'})

    def test_foreign_ca_rejected_at_tls(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)): self.call(identity='untrusted')

    def test_expired_client_rejected_at_tls(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)): self.call(identity='expired')

    def test_wrong_eku_rejected_at_tls(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)): self.call(identity='wrong-eku')

    def test_valid_ca_does_not_authorize_other_client(self):
        self.assertEqual(self.call(identity='unregistered')[0], 403)

    def test_spoofed_internal_metadata_is_rebuilt(self):
        forged = {key: 'fake' for key in INTERNAL_HEADERS}
        forged['X-Internal-MTLS-Verified'] = 'SUCCESS'
        forged['x-internal-mtls-fingerprint'] = 'also-fake'  # Case-insensitive duplicate.
        status, result = self.call(headers=forged)
        self.assertEqual(status, 200)
        self.assertEqual(result['client_fingerprint'], self.fingerprint)
        self.assertEqual(result['credential_version'], CREDENTIAL_VERSION)
        self.assertEqual(result['client_serial'], self.serial)
        self.assertNotIn('fake', json.dumps(result))

    def test_backend_rejects_direct_access_without_service_identity(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(target='backend', identity=None, headers=self.metadata())

    def test_public_android_credential_cannot_authenticate_internal_service(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call(target='backend', headers=self.metadata())

    def test_internal_ca_alone_does_not_authorize_another_service(self):
        self.assertEqual(self.call(target='backend', identity='other-service', headers=self.metadata())[0], 403)

    def test_trusted_gateway_still_requires_valid_metadata(self):
        self.assertEqual(self.call(target='backend', identity='gateway-internal')[0], 400)
        bad = self.metadata(); bad['X-Internal-MTLS-Fingerprint'] = 'fake'
        self.assertEqual(self.call(target='backend', identity='gateway-internal', headers=bad)[0], 403)
        bad = self.metadata(); bad['X-Internal-MTLS-Verified'] = 'FAILED'
        self.assertEqual(self.call(target='backend', identity='gateway-internal', headers=bad)[0], 403)

    def test_backend_binds_only_loopback_and_refuses_vm_interface(self):
        self.assertEqual(self.servers['backend'].server_address[0], '127.0.0.1')
        try:
            interfaces = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global']))
        except (FileNotFoundError, subprocess.CalledProcessError):
            self.skipTest('Sem comando ip; binding loopback foi verificado.')
        addresses = [a['local'] for i in interfaces for a in i.get('addr_info', []) if a['family'] == 'inet']
        if not addresses: self.skipTest('Sem interface IPv4 não loopback para testar acesso direto.')
        for address in addresses:
            with self.assertRaises(OSError):
                with socket.create_connection((address, self.servers['backend'].server_port), timeout=1): pass

    def test_mtls_does_not_replace_user_session_or_accept_invalid_jwt(self):
        for token in [None, 'invalid-token', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.']:
            self.assertEqual(self.call('/account', token=token)[0], 401)

    def test_login_mfa_session_account_and_logout(self):
        status, session = self.call('/session', data=self.credentials())
        self.assertEqual(status, 200)
        status, account = self.call('/account', token=session['session_token'])
        self.assertEqual(status, 200); self.assertEqual(account['account'], 'alice')
        self.assertEqual(self.call('/logout', data={}, token=session['session_token'])[0], 200)
        self.assertEqual(self.call('/account', token=session['session_token'])[0], 401)

    def test_bad_password_and_totp_replay_rejected(self):
        data = self.credentials()
        self.assertEqual(self.call('/session', data=dict(data, password='wrong'))[0], 401)
        self.assertEqual(self.call('/session', data=data)[0], 200)
        self.assertEqual(self.call('/session', data=data)[0], 401)

    def test_expired_session_rejected(self):
        _, session = self.call('/session', data=self.credentials())
        with closing(auth.connect(self.state)) as db, db: db.execute('UPDATE sessions SET expires=0')
        self.assertEqual(self.call('/account', token=session['session_token'])[0], 401)

    def test_disabling_generation_blocks_existing_session(self):
        _, session = self.call('/session', data=self.credentials())
        policy = json.loads(self.policy); policy[self.fingerprint]['enabled'] = False
        (self.state / 'gateway-policy.json').write_text(json.dumps(policy))
        self.assertEqual(self.call('/account', token=session['session_token'])[0], 403)

    def test_two_copies_are_same_identity_and_do_not_bind_token_to_device(self):
        private, cert, _ = pkcs12.load_key_and_certificates((self.state / 'shared-client.p12').read_bytes(),
                                                         (self.state / 'p12-password').read_bytes())
        pki.save_key(self.state / 'copy-b.key', private)
        (self.state / 'copy-b.crt').write_bytes(cert.public_bytes(pki.PEM))
        self.assertEqual(self.call(identity='copy-b')[1]['client_fingerprint'], self.fingerprint)
        _, session = self.call('/session', data=self.credentials())
        self.assertEqual(self.call('/account', identity='copy-b', token=session['session_token'])[0], 200)

    def test_no_provisioning_or_business_routes_on_public_health(self):
        for path in ['/provision', '/bootstrap/login', '/rasp/demo']:
            self.assertEqual(self.call(path, data={})[0], 404)
        self.assertEqual(self.call('/account', target='primary', identity=None)[0], 404)

    def test_pin_listeners_have_valid_tls_distinct_keys(self):
        for target in ['primary', 'backup', 'unpinned']:
            self.assertEqual(self.call('/health', target=target, identity=None)[0], 200)
        self.assertEqual(len({pki.spki_pin(pki.load_cert(self.state, n))
                             for n in ['server', 'backup-server', 'unpinned-server']}), 3)

    def test_generated_inputs_keep_password_and_p12_outside_source(self):
        root = Path(self.temp.name) / 'generated'
        pki.prepare_android(root, self.state)
        local = root / '.local'
        self.assertTrue((local / 'generated-assets/mtls/client.p12').read_bytes() == (self.state / 'shared-client.p12').read_bytes())
        xml = ET.parse(local / 'generated-res/xml/network_security_config.xml').getroot()
        self.assertIsNone(xml.find('debug-overrides'))
        domain = xml.find('domain-config')
        self.assertEqual(domain.find('trust-anchors/certificates').get('overridePins'), 'false')
        self.assertIsNone(domain.find('pin-set').get('expiration'))
        self.assertEqual({pin.text for pin in domain.findall('pin-set/pin')},
                         {pki.spki_pin(pki.load_cert(self.state, n)) for n in ['server', 'backup-server']})
        self.assertFalse((root / 'android').exists())

    def test_gateway_fails_closed_when_internal_server_untrusted(self):
        correct = self.edge.backend_tls
        try:
            self.edge.backend_tls = ssl.create_default_context(cafile=self.state / 'ca.crt')
            self.assertEqual(self.call()[0], 502)
        finally:
            self.edge.backend_tls = correct

    def test_gateway_fails_closed_when_internal_client_identity_missing(self):
        correct = self.edge.backend_tls
        try:
            self.edge.backend_tls = ssl.create_default_context(cafile=self.state / 'internal-ca.crt')
            self.assertEqual(self.call()[0], 502)
        finally:
            self.edge.backend_tls = correct

    def test_oversized_body_rejected_before_reading(self):
        conn = http.client.HTTPSConnection('localhost', self.servers['edge'].server_port, context=self.client(), timeout=3)
        try:
            conn.putrequest('POST', '/session'); conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', '20000'); conn.endheaders()
            self.assertEqual(conn.getresponse().status, 413)
        finally: conn.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
