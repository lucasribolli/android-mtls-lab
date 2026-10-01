#!/usr/bin/env python3
"""Laboratório separado: credencial mTLS compartilhada, pinning e RASP simulado."""
import argparse
from contextlib import closing
import getpass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import secrets
import signal
import socket
import ssl
import threading
import time

from cryptography import x509
import auth
import pki
from rasp import DemoRasp, BankRaspNotIntegrated

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / '.local/shared'
LOG = logging.getLogger('shared-lab')


def initialize(state):
    pki.initialize(state)
    auth.initialize(state)
    with closing(auth.connect(state)) as db, db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS grants (
                digest TEXT PRIMARY KEY, account TEXT NOT NULL, challenge TEXT NOT NULL,
                expires REAL NOT NULL, request_digest TEXT);
            CREATE TABLE IF NOT EXISTS sessions (
                digest TEXT PRIMARY KEY, account TEXT NOT NULL, fingerprint TEXT NOT NULL,
                expires REAL NOT NULL);
            INSERT OR IGNORE INTO settings VALUES ('rasp_decision','blocked');
            INSERT OR IGNORE INTO settings VALUES ('credential_active','true');
        ''')
    (state / 'shared.db').chmod(0o600)


def setting(state, name, value=None):
    with closing(auth.connect(state)) as db, db:
        if value is not None:
            db.execute('UPDATE settings SET value=? WHERE name=?', (value, name))
        return db.execute('SELECT value FROM settings WHERE name=?', (name,)).fetchone()[0]


def active_fingerprint(state):
    cert = pki.load_cert(state, 'shared-client')
    if setting(state, 'credential_active') != 'true':
        raise auth.Error(403, 'Credencial compartilhada revogada para TODAS as instalações.')
    if not cert.not_valid_before_utc <= pki.now() < cert.not_valid_after_utc:
        raise auth.Error(403, 'Certificado compartilhado expirado ou ainda não válido.')
    return pki.fingerprint(cert)


def fields(data, names):
    if not isinstance(data, dict) or set(data) != set(names):
        raise auth.Error(400, 'Campos JSON inválidos.')


class Application:
    def __init__(self, state, rasp_mode='demo'):
        self.state = state
        self.rasp = DemoRasp(state) if rasp_mode == 'demo' else BankRaspNotIntegrated()

    def grant(self, token):
        with closing(auth.connect(self.state)) as db:
            row = db.execute('SELECT * FROM grants WHERE digest=?', (auth.digest(token),)).fetchone()
        if row is None or row['expires'] <= time.time():
            raise auth.Error(401, 'Autorização de provisionamento inválida ou expirada.')
        return dict(row)

    def bootstrap(self, path, token, data):
        if path == '/bootstrap/login':
            account = auth.credentials(self.state, data)
            value, challenge = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            expiry = time.time() + auth.GRANT_TTL
            with closing(auth.connect(self.state)) as db, db:
                db.execute('DELETE FROM grants WHERE expires<=?', (time.time(),))
                db.execute('INSERT INTO grants VALUES (?,?,?,?,NULL)',
                           (auth.digest(value), account, challenge, expiry))
            LOG.info('BOOTSTRAP_AUTORIZADO account=%s rasp=SIMULADO', account)
            return dict(bootstrap_token=value, challenge=challenge, expires_at=expiry)
        if path not in {'/rasp/demo', '/provision'}:
            raise auth.Error(404, 'Endpoint inexistente neste listener HTTPS.')
        grant = self.grant(token)
        if path == '/rasp/demo':
            fields(data, ['challenge'])
            if data['challenge'] != grant['challenge']:
                raise auth.Error(403, 'Challenge incorreto.')
            decision = setting(self.state, 'rasp_decision')
            evidence = self.rasp.issue(grant, decision)
            LOG.info('RASP_SIMULADO account=%s decision=%s sem_deteccao_real=true', grant['account'], decision)
            return dict(evidence=evidence, mode=self.rasp.mode, decision=decision)
        fields(data, ['challenge', 'rasp_evidence'])
        if data['challenge'] != grant['challenge']:
            raise auth.Error(403, 'Challenge incorreto.')
        self.rasp.verify(data['rasp_evidence'], grant)
        # A configuração do operador tem efeito também sobre evidências ainda válidas.
        if setting(self.state, 'rasp_decision') != 'approved':
            raise auth.Error(403, 'Operador bloqueou a entrega no RASP SIMULADO.')
        fp = active_fingerprint(self.state)
        digest = auth.digest(json.dumps(data, sort_keys=True, separators=(',', ':')))
        with closing(auth.connect(self.state)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM grants WHERE digest=?', (grant['digest'],)).fetchone()
            if row is None or row['expires'] <= time.time():
                raise auth.Error(401, 'Autorização expirada.')
            if row['request_digest'] not in {None, digest}:
                raise auth.Error(409, 'Autorização já consumida por outro pedido.')
            db.execute('UPDATE grants SET request_digest=? WHERE digest=?', (digest, grant['digest']))
        LOG.info('CREDENCIAL_COMPARTILHADA_ENTREGUE account=%s fingerprint=%s rasp=SIMULADO', grant['account'], fp)
        return pki.bundle(self.state)

    def api(self, path, token, data, certificate, tls_version):
        fp = pki.fingerprint(x509.load_der_x509_certificate(certificate))
        if not secrets.compare_digest(fp, active_fingerprint(self.state)):
            raise auth.Error(403, 'Certificado assinado pela CA, mas não autorizado como credencial compartilhada.')
        if path == '/identity' and data is None:
            return dict(fingerprint=fp, scope='SHARED_ALL_INSTALLATIONS', unique_device_identity=False)
        if path == '/session' and data is not None:
            account = auth.credentials(self.state, data)
            value, expiry = secrets.token_urlsafe(32), time.time() + auth.SESSION_TTL
            with closing(auth.connect(self.state)) as db, db:
                db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
                db.execute('INSERT INTO sessions VALUES (?,?,?,?)', (auth.digest(value), account, fp, expiry))
            LOG.info('SESSAO_USUARIO_CRIADA account=%s identidade_mtls=COMPARTILHADA tls=%s', account, tls_version)
            return dict(session_token=value, expires_at=expiry, account=account)
        with closing(auth.connect(self.state)) as db:
            session = db.execute('SELECT * FROM sessions WHERE digest=?', (auth.digest(token),)).fetchone()
        if session is None or session['expires'] <= time.time() or session['fingerprint'] != fp:
            raise auth.Error(401, 'Sessão de usuário ausente, expirada ou inválida.')
        if path == '/account' and data is None:
            LOG.info('CONTA_ACESSADA account=%s fingerprint=%s tls=%s', session['account'], fp, tls_version)
            return dict(account=session['account'], certificate_fingerprint=fp, tls=tls_version,
                        unique_device_identity=False, rasp='SIMULADO; verificado somente na entrega',
                        message='Login identifica o usuário. Este certificado NÃO distingue instalações.')
        if path == '/logout' and data == {}:
            with closing(auth.connect(self.state)) as db, db:
                db.execute('DELETE FROM sessions WHERE digest=?', (auth.digest(token),))
            return dict(logged_out=True)
        raise auth.Error(404, 'Endpoint inexistente neste listener mTLS.')


class Handler(BaseHTTPRequestHandler):
    server_version = 'SharedMtlsLab/1.0'

    def log_message(self, format, *args):
        pass  # Não registrar headers, corpo, token, senha ou query string.

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, post):
        status, result = 200, None
        try:
            if '?' in self.path or len(self.path) > 100:
                raise auth.Error(400, 'Use somente o caminho do endpoint.')
            if self.headers.get('Transfer-Encoding'):
                raise auth.Error(400, 'Transfer-Encoding não suportado.')
            data = None
            if post:
                if self.headers.get_content_type() != 'application/json':
                    raise auth.Error(415, 'Use application/json.')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not lengths[0].isdecimal():
                    raise auth.Error(400, 'Content-Length inválido.')
                size = int(lengths[0])
                if not 0 < size <= 16384:
                    raise auth.Error(413, 'Corpo excede o limite.')
                body = self.rfile.read(size)
                if len(body) != size:
                    raise auth.Error(400, 'Corpo incompleto.')
                try:
                    data = json.loads(body)
                except (ValueError, UnicodeError):
                    raise auth.Error(400, 'JSON inválido.')
            headers = self.headers.get_all('Authorization', [])
            if len(headers) > 1:
                raise auth.Error(400, 'Authorization duplicado.')
            bearer = headers[0] if headers else ''
            token = bearer[7:] if bearer.startswith('Bearer ') else ''
            if len(token) > 256:
                raise auth.Error(400, 'Token grande demais.')
            if self.server.kind != 'mtls':
                if not post and self.path == '/health':
                    result = dict(status='ok', listener=self.server.kind, rasp=self.server.app.rasp.mode)
                elif self.server.kind == 'bootstrap' and post:
                    result = self.server.app.bootstrap(self.path, token, data)
                else:
                    raise auth.Error(404, 'Endpoint indisponível neste listener.')
            else:
                result = self.server.app.api(self.path, token, data, self.connection.getpeercert(binary_form=True),
                                             self.connection.version())
        except auth.Error as error:
            status, result = error.status, {'error': str(error)}
        except (socket.timeout, ConnectionError):
            return
        except Exception:
            # Não imprimir exceções potencialmente contendo entradas sensíveis.
            LOG.error('ERRO_INTERNO listener=%s', self.server.kind)
            status, result = 500, {'error': 'Erro interno; consulte os testes e a configuração local.'}
        try:
            body = json.dumps(result, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ssl.SSLError):
            pass
        LOG.info('HTTP listener=%s status=%d', self.server.kind, status)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app, kind, context):
        self.app, self.kind, self.context = app, kind, context
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(10)
            with self.context.wrap_socket(request, server_side=True) as tls:
                self.finish_request(tls, address)
        except (OSError, ssl.SSLError):
            LOG.info('TLS_RECUSADO_OU_CONEXAO_ENCERRADA listener=%s', self.kind)
        finally:
            self.shutdown_request(request)
            self.slots.release()


def context(state, name='server', mtls=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(state / (name + '.crt'), state / (name + '.key'))
    if mtls:
        ctx.load_verify_locations(state / 'ca.crt')
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def check(state):
    if not (state / 'ready').exists():
        raise RuntimeError('Execute scripts/prepare.sh primeiro.')
    for name in ['ca', 'server', 'backup-server', 'unpinned-server', 'shared-client']:
        cert = pki.load_cert(state, name)
        if not cert.not_valid_before_utc <= pki.now() < cert.not_valid_after_utc:
            raise RuntimeError(f'{name}.crt expirado ou ainda não válido. Consulte renovação no README.')
    context(state)
    context(state, mtls=True)
    if not (state / 'shared.db').exists():
        raise RuntimeError('Banco local ausente: execute prepare.sh.')


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=STATE)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    sub.add_parser('check')
    create = sub.add_parser('create-user')
    create.add_argument('account')
    create.add_argument('--output', type=Path, required=True)
    rasp = sub.add_parser('rasp')
    rasp.add_argument('decision', choices=['approved', 'blocked', 'unavailable'])
    credential = sub.add_parser('credential')
    credential.add_argument('decision', choices=['active', 'revoked'])
    serve = sub.add_parser('serve')
    serve.add_argument('--diagnostics', action='store_true')
    serve.add_argument('--rasp-provider', choices=['demo', 'bank'], default='demo')
    args = parser.parse_args()
    state = args.state.resolve()
    if args.command == 'init':
        initialize(state)
        pki.prepare_android(ROOT, state)
        print('PKI pronta; pins públicos gerados; RASP SIMULADO começa bloqueado.')
    elif args.command == 'check':
        check(state)
        print('Estado local e certificados válidos.')
    elif args.command == 'create-user':
        # Destino exclusivo evita truncar um arquivo existente antes de cadastrar.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream:
            args.output.chmod(0o600)
            try:
                result = auth.create_user(state, args.account, getpass.getpass('Senha (mínimo 12 caracteres): '))
                json.dump(result, stream, indent=2)
            except Exception:
                args.output.unlink()
                raise
        print(f'Segredo TOTP privado salvo em {args.output}. Importe em um autenticador; não publique.')
    elif args.command == 'rasp':
        setting(state, 'rasp_decision', args.decision)
        LOG.info('RASP_SIMULADO_CONFIGURADO decision=%s', args.decision)
    elif args.command == 'credential':
        setting(state, 'credential_active', 'true' if args.decision == 'active' else 'false')
        LOG.info('CREDENCIAL_COMPARTILHADA decision=%s afeta_todas_instalacoes=true', args.decision)
    elif args.command == 'serve':
        check(state)
        app = Application(state, args.rasp_provider)
        listeners = [('mtls', 8543, 'server'), ('bootstrap', 8544, 'server')]
        if args.diagnostics:
            listeners += [('unpinned', 8545, 'unpinned-server'), ('backup', 8546, 'backup-server')]
        servers = []
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        try:
            for kind, port, name in listeners:
                server = Server(('127.0.0.1', port), app, kind, context(state, name, kind == 'mtls'))
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                LOG.info('LISTENER https://localhost:%s tipo=%s rasp=%s', port, kind, app.rasp.mode)
            stop.wait()
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
