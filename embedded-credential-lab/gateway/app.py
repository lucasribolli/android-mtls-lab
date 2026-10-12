"""Edge: termina o mTLS Android e inicia OUTRA conexão TLS autenticada ao backend."""
import argparse
import http.client
import json
import logging
import ssl
from common import pki
from common.config import STATE, PORTS
from common.http import Error, Server, exactly_one, serve
from gateway.policy import from_handshake

LOG = logging.getLogger('gateway')
API_PATHS = {'/identity', '/session', '/account', '/logout'}


def external_context(state, certificate='server', require_client=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(state / (certificate + '.crt'), state / (certificate + '.key'))
    if require_client:
        ctx.load_verify_locations(state / 'ca.crt')
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def internal_context(state):
    ctx = ssl.create_default_context(cafile=state / 'internal-ca.crt')
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(state / 'gateway-internal.crt', state / 'gateway-internal.key')
    return ctx  # Hostname localhost é validado pelo HTTPSConnection.


class Gateway:
    paths = API_PATHS

    def __init__(self, state, backend_port=PORTS['backend']):
        self.state, self.backend_port = state, backend_port
        self.backend_tls = internal_context(state)

    def handle(self, request, data):
        metadata = from_handshake(self.state, request.connection.getpeercert(binary_form=True))
        # NÃO copiar inbound headers. Inclusive nomes reservados, duplicados,
        # casing alternativo, Connection, X-Forwarded-* e Host são descartados.
        # Somente Authorization é encaminhado; os quatro headers são criados aqui.
        headers = {'Content-Type': 'application/json', 'Connection': 'close', **metadata}
        authorization = exactly_one(request.headers, 'Authorization')
        if authorization:
            headers['Authorization'] = authorization
        stripped = any(name.lower().startswith('x-internal-mtls-') for name in request.headers)
        LOG.info('EDGE_MTLS_VERIFIED version=%s fingerprint=%s tls=%s spoofed_headers_removed=%s',
                 metadata['X-Internal-MTLS-Version'], metadata['X-Internal-MTLS-Fingerprint'],
                 request.connection.version(), stripped)
        connection = http.client.HTTPSConnection('localhost', self.backend_port, context=self.backend_tls, timeout=8)
        try:
            connection.request(request.command, request.path,
                               json.dumps(data).encode() if data is not None else None, headers)
            response = connection.getresponse()
            body = response.read(32769)
            if len(body) > 32768:
                raise ValueError('Backend response too large')
            return response.status, json.loads(body)
        except (OSError, ValueError, http.client.HTTPException) as error:
            LOG.warning('BACKEND_INDISPONIVEL type=%s', type(error).__name__)
            raise Error(502, 'Backend interno indisponível ou canal TLS inválido.') from error
        finally:
            connection.close()


class Health:
    paths = {'/health'}

    def __init__(self, label):
        self.label = label

    def handle(self, request, data):
        if request.command != 'GET':
            raise Error(405, 'Use GET.')
        return 200, {'status': 'ok', 'listener': self.label, 'mtls_termination': 'gateway',
                     'dexguard': 'NOT AVAILABLE / NOT VALIDATED', 'rasp': 'NOT ACTIVE / NOT VALIDATED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    pki.check(STATE)
    servers = []
    try:
        servers.append(Server(('127.0.0.1', PORTS['gateway']), external_context(STATE), Gateway(STATE), 'gateway-mtls'))
        servers.append(Server(('127.0.0.1', PORTS['health']), external_context(STATE, require_client=False), Health('primary'), 'gateway-health'))
        if args.diagnostics:
            for name, cert in [('unpinned', 'unpinned-server'), ('backup', 'backup-server')]:
                servers.append(Server(('127.0.0.1', PORTS[name]), external_context(STATE, cert, False), Health(name), 'gateway-' + name))
    except Exception:
        for server in servers:
            server.server_close()
        raise
    serve(servers)


if __name__ == '__main__':
    main()
