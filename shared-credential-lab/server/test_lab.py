"""Testes de integração com TLS real, estado descartável e duas cópias da identidade."""
import base64
from contextlib import closing
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import auth
import lab
import pki
from rasp import BankRaspNotIntegrated


class SharedLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.state = Path(cls.temp.name) / 'state'
        lab.initialize(cls.state)
        cls.app = lab.Application(cls.state)
        cls.servers = {}
        for kind, name in [('bootstrap', 'server'), ('mtls', 'server'),
                           ('unpinned', 'unpinned-server'), ('backup', 'backup-server')]:
            server = lab.Server(('127.0.0.1', 0), cls.app, kind, lab.context(cls.state, name, kind == 'mtls'))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers[kind] = server

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers.values():
            server.shutdown(); server.server_close()
        cls.temp.cleanup()

    def setUp(self):
        lab.setting(self.state, 'rasp_decision', 'approved')
        lab.setting(self.state, 'credential_active', 'true')
        with closing(auth.connect(self.state)) as db, db:
            for table in ['users', 'auth_limits', 'grants', 'sessions']:
                db.execute('DELETE FROM ' + table)
        self.password = 'laboratory-password-123'
        self.user = auth.create_user(self.state, 'alice', self.password)
        self.other = auth.create_user(self.state, 'bob', self.password)
        self.app.rasp = lab.DemoRasp(self.state)

    def credentials(self, user=None, offset=0):
        user = user or self.user
        return dict(account=user['account'], password=self.password,
                    otp=auth.totp(user['totp_secret'], int(time.time() // 30) + offset))

    def tls(self, certificate=None):
        ctx = ssl.create_default_context(cafile=self.state / 'ca.crt')
        if certificate:
            ctx.load_cert_chain(self.state / (certificate + '.crt'), self.state / (certificate + '.key'))
        return ctx

    def call(self, kind, path, data=None, token=None, certificate=None, ctx=None):
        conn = http.client.HTTPSConnection('localhost', self.servers[kind].server_port,
                                          context=ctx or self.tls(certificate), timeout=5)
        headers = {'Content-Type': 'application/json'}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + token
        try:
            conn.request('POST' if data is not None else 'GET', path,
                         json.dumps(data) if data is not None else None, headers)
            response = conn.getresponse()
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def grant(self, user=None):
        status, result = self.call('bootstrap', '/bootstrap/login', self.credentials(user))
        self.assertEqual(status, 200, result)
        return result

    def evidence(self, grant):
        return self.call('bootstrap', '/rasp/demo', {'challenge': grant['challenge']}, grant['bootstrap_token'])

    def provision(self, grant):
        status, evidence = self.evidence(grant)
        self.assertEqual(status, 200, evidence)
        data = dict(challenge=grant['challenge'], rasp_evidence=evidence['evidence'])
        return data, self.call('bootstrap', '/provision', data, grant['bootstrap_token'])

    def test_01_two_deliveries_same_private_key_and_certificate(self):
        bundles = []
        for user, name in [(self.user, 'copy-a'), (self.other, 'copy-b')]:
            _, (status, bundle) = self.provision(self.grant(user))
            self.assertEqual(status, 200, bundle)
            key, cert, _ = pkcs12.load_key_and_certificates(base64.b64decode(bundle['p12_base64']),
                                                          bundle['p12_password'].encode())
            pki.save_key(self.state / (name + '.key'), key)
            (self.state / (name + '.crt')).write_bytes(cert.public_bytes(pki.PEM))
            bundles.append(bundle)
        self.assertEqual(bundles[0], bundles[1])
        for name in ['copy-a', 'copy-b']:
            status, result = self.call('mtls', '/identity', certificate=name)
            self.assertEqual(status, 200)
            self.assertFalse(result['unique_device_identity'])
            self.assertEqual(result['fingerprint'], bundles[0]['certificate_fingerprint'])

    def test_02_mtls_without_certificate_fails(self):
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            self.call('mtls', '/identity')

    def test_03_mtls_certificate_does_not_authorize_account(self):
        status, _ = self.call('mtls', '/account', certificate='shared-client')
        self.assertEqual(status, 401)

    def test_04_session_account_logout_and_no_installation_binding(self):
        status, session = self.call('mtls', '/session', self.credentials(), certificate='shared-client')
        self.assertEqual(status, 200)
        token = session['session_token']
        # Uma cópia independente da mesma chave também satisfaz mTLS para o token.
        # Demonstra a ausência de vínculo criptográfico a uma instalação, não autorização para outra conta.
        for name in ['shared-client', 'duplicate']:
            if name == 'duplicate':
                for suffix in ['.crt', '.key']:
                    (self.state / (name + suffix)).write_bytes((self.state / ('shared-client' + suffix)).read_bytes())
            status, result = self.call('mtls', '/account', token=token, certificate=name)
            self.assertEqual(status, 200)
            self.assertEqual(result['account'], 'alice')
        self.assertEqual(self.call('mtls', '/logout', {}, token, 'shared-client')[0], 200)
        self.assertEqual(self.call('mtls', '/account', token=token, certificate='shared-client')[0], 401)

    def test_05_no_bootstrap_authorization_no_bundle(self):
        status, response = self.call('bootstrap', '/provision', {'challenge': 'x', 'rasp_evidence': 'x'})
        self.assertEqual(status, 401)
        self.assertNotIn('p12_base64', response)

    def test_06_blocked_rasp_no_bundle(self):
        lab.setting(self.state, 'rasp_decision', 'blocked')
        _, (status, result) = self.provision(self.grant())
        self.assertEqual(status, 403)
        self.assertNotIn('p12_base64', result)

    def test_07_unavailable_rasp_fails_closed(self):
        lab.setting(self.state, 'rasp_decision', 'unavailable')
        self.assertEqual(self.evidence(self.grant())[0], 503)

    def test_08_tampered_rasp_evidence(self):
        grant = self.grant()
        _, evidence = self.evidence(grant)
        payload, signature = evidence['evidence'].split('.')
        signature = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        status, _ = self.call('bootstrap', '/provision',
                             dict(challenge=grant['challenge'], rasp_evidence=payload + '.' + signature),
                             grant['bootstrap_token'])
        self.assertEqual(status, 403)

    def test_09_evidence_cannot_be_reused_for_other_grant(self):
        a, b = self.grant(), self.grant(self.other)
        _, evidence = self.evidence(a)
        status, _ = self.call('bootstrap', '/provision',
                             dict(challenge=b['challenge'], rasp_evidence=evidence['evidence']), b['bootstrap_token'])
        self.assertEqual(status, 403)

    def test_10_expired_evidence(self):
        grant = self.grant()
        with patch('rasp.time.time', return_value=time.time() - 120):
            _, evidence = self.evidence(grant)
        status, _ = self.call('bootstrap', '/provision',
                             dict(challenge=grant['challenge'], rasp_evidence=evidence['evidence']), grant['bootstrap_token'])
        self.assertEqual(status, 403)

    def test_11_exact_retry_idempotent_other_request_conflicts(self):
        grant = self.grant()
        data, (status, first) = self.provision(grant)
        self.assertEqual(status, 200)
        status, second = self.call('bootstrap', '/provision', data, grant['bootstrap_token'])
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        self.assertEqual(self.provision(grant)[1][0], 409)

    def test_12_operator_can_block_issued_evidence(self):
        grant = self.grant()
        _, evidence = self.evidence(grant)
        lab.setting(self.state, 'rasp_decision', 'blocked')
        status, _ = self.call('bootstrap', '/provision',
                             dict(challenge=grant['challenge'], rasp_evidence=evidence['evidence']), grant['bootstrap_token'])
        self.assertEqual(status, 403)

    def test_13_global_revocation_blocks_existing_sessions_and_delivery(self):
        _, session = self.call('mtls', '/session', self.credentials(), certificate='shared-client')
        grant = self.grant(self.other)
        lab.setting(self.state, 'credential_active', 'false')
        self.assertEqual(self.call('mtls', '/account', token=session['session_token'], certificate='shared-client')[0], 403)
        self.assertEqual(self.provision(grant)[1][0], 403)

    def test_14_ca_signature_alone_not_authorization(self):
        key = pki.key()
        ca_key = serialization.load_pem_private_key((self.state / 'ca.key').read_bytes(), None)
        cert = pki.issue(key.public_key(), 'another-client', pki.load_cert(self.state, 'ca'), ca_key, True)
        pki.save_key(self.state / 'other.key', key)
        (self.state / 'other.crt').write_bytes(cert.public_bytes(pki.PEM))
        self.assertEqual(self.call('mtls', '/identity', certificate='other')[0], 403)

    def test_15_password_mfa_and_replay(self):
        creds = self.credentials()
        wrong = dict(creds, password='incorrect-password')
        self.assertEqual(self.call('bootstrap', '/bootstrap/login', wrong)[0], 401)
        self.assertEqual(self.call('bootstrap', '/bootstrap/login', creds)[0], 200)
        self.assertEqual(self.call('bootstrap', '/bootstrap/login', creds)[0], 401)

    def test_16_bank_rasp_placeholder_never_approves(self):
        grant = self.grant()
        self.app.rasp = BankRaspNotIntegrated()
        self.assertEqual(self.evidence(grant)[0], 503)
        status, _ = self.call('bootstrap', '/provision', dict(challenge=grant['challenge'], rasp_evidence='fake'),
                             grant['bootstrap_token'])
        self.assertEqual(status, 503)

    def test_17_pin_diagnostics_are_valid_tls_but_distinct_keys(self):
        # Python valida CA/hostname. Pinning Android é testado separadamente no aparelho.
        for kind in ['bootstrap', 'unpinned', 'backup']:
            self.assertEqual(self.call(kind, '/health')[0], 200)
        self.assertNotEqual(pki.spki_pin(pki.load_cert(self.state, 'server')),
                            pki.spki_pin(pki.load_cert(self.state, 'unpinned-server')))

    def test_18_generated_android_pins_and_ca_no_bypass(self):
        root = Path(self.temp.name) / 'android-config'
        pki.prepare_android(root, self.state)
        xml = ET.parse(root / 'android/app/src/debug/res/xml/network_security_config.xml').getroot()
        self.assertIsNone(xml.find('debug-overrides'))
        domain = xml.find('domain-config')
        self.assertEqual(domain.find('domain').text, 'localhost')
        self.assertEqual(domain.find('trust-anchors/certificates').get('overridePins'), 'false')
        self.assertIsNone(domain.find('pin-set').get('expiration'))
        self.assertEqual({p.text for p in domain.findall('pin-set/pin')},
                         {pki.spki_pin(pki.load_cert(self.state, name)) for name in ['server', 'backup-server']})

    def test_19_http_listener_isolation_and_oversized_body(self):
        self.assertEqual(self.call('bootstrap', '/account')[0], 404)
        self.assertEqual(self.call('unpinned', '/bootstrap/login', self.credentials())[0], 404)
        # Enviar apenas headers: o servidor recusa antes de ler um corpo excessivo.
        conn = http.client.HTTPSConnection('localhost', self.servers['bootstrap'].server_port,
                                          context=self.tls(), timeout=5)
        try:
            conn.putrequest('POST', '/bootstrap/login')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', '17000')
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 413)
        finally:
            conn.close()

    def test_20_expired_grant_and_session(self):
        grant = self.grant()
        _, session = self.call('mtls', '/session', self.credentials(self.other), certificate='shared-client')
        with closing(auth.connect(self.state)) as db, db:
            db.execute('UPDATE grants SET expires=0')
            db.execute('UPDATE sessions SET expires=0')
        self.assertEqual(self.evidence(grant)[0], 401)
        self.assertEqual(self.call('mtls', '/account', token=session['session_token'], certificate='shared-client')[0], 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
