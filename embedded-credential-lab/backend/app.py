"""Representa Spring atrás do edge; peer TLS aqui é o SERVIÇO gateway, nunca Android."""
from contextlib import closing
import logging
import secrets
import ssl
import time
from cryptography import x509
from backend import auth
from common import pki
from common.config import STATE, PORTS, INTERNAL_HEADERS
from common.http import Error, Server, exactly_one, serve
from gateway.policy import allowed

LOG = logging.getLogger('backend')


def initialize(state):
    auth.initialize(state)
    with closing(auth.connect(state)) as db, db:
        db.execute('''CREATE TABLE IF NOT EXISTS sessions (
            digest TEXT PRIMARY KEY, account TEXT NOT NULL, fingerprint TEXT NOT NULL,
            expires REAL NOT NULL)''')
    (state / 'backend.db').chmod(0o600)


def context(state):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(state / 'backend-internal.crt', state / 'backend-internal.key')
    ctx.load_verify_locations(state / 'internal-ca.crt')
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class Backend:
    paths = {'/identity', '/session', '/account', '/logout'}

    def __init__(self, state):
        self.state = state
        self.trusted_gateway = pki.fingerprint(pki.load_cert(state, 'gateway-internal'))

    def metadata(self, request):
        # Esta é identidade TLS de SERVIÇO, separada da identidade Android no edge.
        der = request.connection.getpeercert(binary_form=True)
        if not der or not secrets.compare_digest(pki.fingerprint(x509.load_der_x509_certificate(der)), self.trusted_gateway):
            raise Error(403, 'Serviço chamador não é o gateway autorizado.')
        metadata = {name: exactly_one(request.headers, name, required=True) for name in INTERNAL_HEADERS}
        if metadata['X-Internal-MTLS-Verified'] != 'SUCCESS':
            raise Error(403, 'Gateway não informou mTLS verificado.')
        entry = allowed(self.state, metadata['X-Internal-MTLS-Fingerprint'])
        if (metadata['X-Internal-MTLS-Serial'] != entry['serial']
                or metadata['X-Internal-MTLS-Version'] != entry['version']):
            raise Error(403, 'Metadata inconsistente com a política.')
        return metadata

    def handle(self, request, data):
        metadata = self.metadata(request)
        identity = {'verified': True, 'credential_version': metadata['X-Internal-MTLS-Version'],
                    'client_fingerprint': metadata['X-Internal-MTLS-Fingerprint'],
                    'client_serial': metadata['X-Internal-MTLS-Serial'], 'unique_device_identity': False,
                    'mtls_termination': 'API_GATEWAY', 'internal_peer': 'gateway-internal',
                    'internal_tls': request.connection.version()}
        path, method = request.path, request.command
        if path == '/identity' and method == 'GET':
            return 200, identity  # Sem dados de conta.
        if path == '/session' and method == 'POST':
            try:
                account = auth.credentials(self.state, data)
            except auth.Error as error:
                raise Error(error.status, str(error)) from error
            token, expiry = secrets.token_urlsafe(32), time.time() + auth.SESSION_TTL
            with closing(auth.connect(self.state)) as db, db:
                db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
                db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                           (auth.digest(token), account, identity['client_fingerprint'], expiry))
            LOG.info('USER_SESSION_CREATED account=%s gateway_verified=true', account)
            return 200, {'session_token': token, 'expires_at': expiry, 'account': account}
        authorization = exactly_one(request.headers, 'Authorization')
        token = authorization[7:] if authorization.startswith('Bearer ') else ''
        with closing(auth.connect(self.state)) as db:
            session = db.execute('SELECT * FROM sessions WHERE digest=?', (auth.digest(token),)).fetchone()
        if not session or session['expires'] <= time.time() or session['fingerprint'] != identity['client_fingerprint']:
            raise Error(401, 'Sessão de usuário ausente, inválida ou expirada; mTLS não substitui login.')
        if path == '/account' and method == 'GET':
            LOG.info('ACCOUNT_AUTHORIZED account=%s', session['account'])
            return 200, {'account': session['account'], 'mtls': identity,
                         'authorization': 'opaque user session verified by internal backend'}
        if path == '/logout' and method == 'POST' and data == {}:
            with closing(auth.connect(self.state)) as db, db:
                db.execute('DELETE FROM sessions WHERE digest=?', (auth.digest(token),))
            return 200, {'logged_out': True}
        raise Error(405, 'Método/corpo não permitido.')


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    pki.check(STATE)
    initialize(STATE)
    # Não aceitar --host nem escutar 0.0.0.0 nesta demonstração de fronteira interna.
    server = Server(('127.0.0.1', PORTS['backend']), context(STATE), Backend(STATE), 'internal-backend')
    serve([server])


if __name__ == '__main__':
    main()
