#!/usr/bin/env python3
"""Banco Lab: login/MFA, atestação Google, sessão e renovação por mTLS."""
import argparse
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import tempfile
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

import auth
from attestation import GoogleAttestation

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local' / 'bank'
LOG = logging.getLogger('mtls-lab')
PEM = serialization.Encoding.PEM
MAX_BODY = 131072

EnrollmentError = auth.Error


def now():
    return datetime.now(timezone.utc)


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def save_key(path, key):
    path.write_bytes(key.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    path.chmod(0o600)


def load_ca(state):
    cert = x509.load_pem_x509_certificate((state / 'ca.crt').read_bytes())
    key = serialization.load_pem_private_key((state / 'ca.key').read_bytes(), None)
    if not cert.not_valid_before_utc <= now() < cert.not_valid_after_utc:
        raise RuntimeError('CA fora da validade; consulte a renovação no README.')
    return cert, key


def leaf_certificate(public_key, cn, ca, ca_key, purpose):
    expires = min(now() + timedelta(days=7 if purpose == ExtendedKeyUsageOID.CLIENT_AUTH else 30),
                  ca.not_valid_after_utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(ca.subject).public_key(public_key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(now() - timedelta(minutes=1)).not_valid_after(expires)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
               .add_extension(x509.KeyUsage(True, False, False, False, False,
                                           False, False, None, None), True)
               .add_extension(x509.ExtendedKeyUsage([purpose]), False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False))
    if purpose == ExtendedKeyUsageOID.SERVER_AUTH:
        import ipaddress
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
    return builder.sign(ca_key, hashes.SHA256())


def renew_server(state):
    ca, key = load_ca(state)
    private = serialization.load_pem_private_key((state / 'server.key').read_bytes(), None)
    cert = leaf_certificate(private.public_key(), 'localhost', ca, key, ExtendedKeyUsageOID.SERVER_AUTH)
    pending = state / 'server.crt.new'
    pending.write_bytes(cert.public_bytes(PEM))
    pending.replace(state / 'server.crt')


def initialize(state):
    """Nova pasta: nenhuma chave privada de cliente é criada no servidor."""
    if not (state / 'ready').exists():
        if state.exists():
            raise RuntimeError(f'Estado incompleto em {state}; preserve e examine antes de continuar.')
        state.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=state.parent, prefix='bank-init-') as temp:
            folder = Path(temp) / 'state'
            folder.mkdir(mode=0o700)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Banco Lab CA')])
            ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                  .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now() - timedelta(minutes=1))
                  .not_valid_after(now() + timedelta(days=365))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                  .add_extension(x509.KeyUsage(False, False, False, False, False,
                                              True, True, None, None), True)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
                  .sign(ca_key, hashes.SHA256()))
            save_key(folder / 'ca.key', ca_key)
            (folder / 'ca.crt').write_bytes(ca.public_bytes(PEM))
            save_key(folder / 'server.key', rsa.generate_private_key(public_exponent=65537, key_size=2048))
            renew_server(folder)
            (folder / 'ready').write_text('Cadastro HTTPS + API mTLS.\n')
            folder.rename(state)
    with closing(database(state)) as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS tokens (
                digest TEXT PRIMARY KEY, account TEXT NOT NULL, expires REAL NOT NULL,
                csr_digest TEXT, device_id TEXT);
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY, account TEXT NOT NULL, fingerprint TEXT UNIQUE NOT NULL,
                certificate TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        ''')
        # Preserva o histórico v2. Identidades antigas não se tornam atestadas por migração.
        columns = {row[1] for row in db.execute('PRAGMA table_info(devices)')}
        for name, kind in [('attested', 'INTEGER NOT NULL DEFAULT 0'),
                           ('attestation_chain', 'TEXT'), ('attestation_result', 'TEXT'),
                           ('attested_at', 'REAL')]:
            if name not in columns:
                db.execute(f'ALTER TABLE devices ADD COLUMN {name} {kind}')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS client_certificates (
                fingerprint TEXT PRIMARY KEY, device_id TEXT NOT NULL, certificate TEXT NOT NULL,
                accept_until REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS renewals (
                old_fingerprint TEXT PRIMARY KEY, new_fingerprint TEXT NOT NULL);
        ''')
    auth.initialize(state)
    (state / 'bank.db').chmod(0o600)


def database(state):
    db = sqlite3.connect(state / 'bank.db', timeout=10)
    db.row_factory = sqlite3.Row
    return db


def public_csr(csr_pem):
    if not isinstance(csr_pem, str) or len(csr_pem) > 8192:
        raise EnrollmentError(400, 'CSR inválido.')
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        public = csr.public_key()
        if not (isinstance(public, rsa.RSAPublicKey) and public.key_size == 2048
                and public.public_numbers().e == 65537
                and csr.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256
                and csr.is_signature_valid):
            raise ValueError('Assinatura ou algoritmo não permitido')
        return public
    except (ValueError, TypeError, x509.InvalidVersion) as exc:
        raise EnrollmentError(400, 'CSR requer RSA-2048 e assinatura SHA256withRSA válida.') from exc


def enrolled_response(state, record):
    return {'device_id': record['id'], 'account': record['account'],
            'certificate': record['certificate'], 'ca': (state / 'ca.crt').read_text(),
            'attestation': json.loads(record['attestation_result'])}


def enroll(state, token, data, attestor):
    if set(data) != {'csr', 'attestation_chain'}:
        raise EnrollmentError(400, 'Envie csr e attestation_chain.')
    public = public_csr(data['csr'])
    request_digest = auth.digest(json.dumps(data, sort_keys=True, separators=(',', ':')))
    with closing(database(state)) as db:
        grant = auth.grant(db, token)
    # Rede e JVM fora da transação. A autorização é revalidada atomicamente ao emitir.
    checked = attestor.verify(data['attestation_chain'], grant['challenge'], public)
    with closing(database(state)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        grant = auth.grant(db, token)
        if grant['device_id']:
            if grant['request_digest'] != request_digest:
                raise EnrollmentError(409, 'Autorização já utilizada para outro pedido.')
            record = db.execute('SELECT * FROM devices WHERE id=? AND active=1 AND attested=1',
                                (grant['device_id'],)).fetchone()
            if record is None:
                raise EnrollmentError(403, 'Identidade revogada.')
            return enrolled_response(state, record)
        device_id = str(uuid.uuid4())
        ca, ca_key = load_ca(state)
        # A conta vem do login/MFA. Subject e extensões solicitados pelo CSR são ignorados.
        cert = leaf_certificate(public, device_id, ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
        record = {'id': device_id, 'account': grant['account'], 'fingerprint': fingerprint(cert),
                  'certificate': cert.public_bytes(PEM).decode(), 'attestation_result': json.dumps(checked)}
        db.execute('''INSERT INTO devices(id,account,fingerprint,certificate,attested,
            attestation_chain,attestation_result,attested_at) VALUES (?,?,?,?,1,?,?,?)''',
                   (device_id, record['account'], record['fingerprint'], record['certificate'],
                    json.dumps(data['attestation_chain']), record['attestation_result'], time.time()))
        db.execute('INSERT INTO client_certificates VALUES (?,?,?,?)',
                   (record['fingerprint'], device_id, record['certificate'], cert.not_valid_after_utc.timestamp()))
        db.execute('UPDATE enrollment_grants SET request_digest=?,device_id=? WHERE digest=?',
                   (request_digest, device_id, grant['digest']))
        LOG.info('ATESTACAO_OK dispositivo=%s nivel=%s boot=%s', device_id,
                 checked['security_level'], checked['boot_state'])
        LOG.info('CADASTRO_EMITIDO dispositivo=%s conta=%s', device_id, grant['account'])
        return enrolled_response(state, record)


def active_device(db, peer):
    record = db.execute('''SELECT d.* FROM devices d JOIN client_certificates c ON c.device_id=d.id
        WHERE c.fingerprint=? AND c.accept_until>? AND d.active=1 AND d.attested=1''',
                        (fingerprint(peer), time.time())).fetchone()
    if record is None:
        raise EnrollmentError(403, 'Identidade não atestada, não cadastrada, expirada ou revogada.')
    return record


def renew_client(state, peer, token, attestor):
    with closing(database(state)) as db:
        device = active_device(db, peer)
        auth.session(db, token, device)
    # Atestação histórica não prova o estado atual do boot. Rechecamos revogação;
    # após 30 dias exigimos novo cadastro/atestação com chave e challenge novos.
    if device['attested_at'] + 30 * 86400 <= time.time():
        raise EnrollmentError(403, 'Atestação tem 30 dias. Faça novo cadastro com login/MFA e nova chave.')
    attestor.check_revocation(json.loads(device['attestation_chain']))
    with closing(database(state)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        device = active_device(db, peer)
        auth.session(db, token, device)
        old = fingerprint(peer)
        pending = db.execute('''SELECT c.* FROM renewals r JOIN client_certificates c
            ON c.fingerprint=r.new_fingerprint WHERE r.old_fingerprint=?''', (old,)).fetchone()
        if pending:
            if pending['accept_until'] <= time.time():
                raise EnrollmentError(409, 'Renovação anterior já superada.')
            pem = pending['certificate']
        else:
            if old != device['fingerprint']:
                raise EnrollmentError(409, 'Use o certificado mais recente.')
            ca, ca_key = load_ca(state)
            cert = leaf_certificate(peer.public_key(), device['id'], ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
            pem = cert.public_bytes(PEM).decode()
            db.execute('INSERT INTO client_certificates VALUES (?,?,?,?)',
                       (fingerprint(cert), device['id'], pem, cert.not_valid_after_utc.timestamp()))
            db.execute('INSERT INTO renewals VALUES (?,?)', (old, fingerprint(cert)))
            db.execute('UPDATE client_certificates SET accept_until=MIN(accept_until,?) WHERE fingerprint=?',
                       (time.time() + 300, old))
            db.execute('UPDATE devices SET certificate=?,fingerprint=? WHERE id=?',
                       (pem, fingerprint(cert), device['id']))
        LOG.info('CERTIFICADO_RENOVADO dispositivo=%s transporte=mtls', device['id'])
        return {'certificate': pem, 'ca': (state / 'ca.crt').read_text(), 'device_id': device['id']}


def tls_context(state, mutual):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(state / 'server.crt', state / 'server.key')
    context.options |= ssl.OP_NO_TICKET
    if mutual:
        context.load_verify_locations(cafile=state / 'ca.crt')
        context.verify_mode = ssl.CERT_REQUIRED
    return context


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode() + b'\n'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def body(self):
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
            raise EnrollmentError(400, 'Content-Length único obrigatório; sem Transfer-Encoding.')
        try:
            length = int(lengths[0])
        except ValueError:
            raise EnrollmentError(400, 'Content-Length inválido.')
        if not 0 < length <= MAX_BODY:
            raise EnrollmentError(413, 'Pedido excede 128 KiB.')
        if self.headers.get_content_type() != 'application/json':
            raise EnrollmentError(415, 'Use application/json.')
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise EnrollmentError(400, 'JSON deve ser um objeto.')
        return data

    def bearer(self):
        values = self.headers.get_all('Authorization', [])
        if len(values) != 1 or not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', values[0]):
            return ''
        return values[0][7:]

    def handle_api(self, post):
        try:
            bootstrap_routes = {'/auth/enrollment', '/enroll'}
            mutual_routes = {'/session', '/logout', '/renew'} if post else {'/account'}
            if not self.server.mutual:
                if not post or self.path not in bootstrap_routes:
                    raise EnrollmentError(404, 'Rota inexistente.')
                data = self.body()
                if self.path == '/auth/enrollment':
                    response = auth.new_grant(self.server.state, data)
                    LOG.info('MFA_OK finalidade=cadastro')
                else:
                    response = enroll(self.server.state, self.bearer(), data, self.server.attestor)
            else:
                if self.path not in mutual_routes:
                    raise EnrollmentError(404, 'Rota inexistente.')
                peer = x509.load_der_x509_certificate(self.connection.getpeercert(binary_form=True))
                with closing(database(self.server.state)) as db:
                    device = active_device(db, peer)
                data = self.body() if post else None
                if self.path == '/session':
                    response = auth.new_session(self.server.state, device, data)
                    LOG.info('SESSAO_CRIADA dispositivo=%s', device['id'])
                else:
                    if post and data:
                        raise EnrollmentError(400, 'Envie um objeto JSON vazio.')
                    with closing(database(self.server.state)) as db, db:
                        device = active_device(db, peer)
                        user_session = auth.session(db, self.bearer(), device)
                        if self.path == '/logout':
                            db.execute('UPDATE sessions SET active=0 WHERE digest=?', (user_session['digest'],))
                            LOG.info('SESSAO_ENCERRADA dispositivo=%s', device['id'])
                    if self.path == '/renew':
                        response = renew_client(self.server.state, peer, self.bearer(), self.server.attestor)
                    elif self.path == '/logout':
                        response = {'logged_out': True}
                    else:
                        response = {'mtls': True, 'user_session': True, 'account': device['account'],
                                    'device_id': device['id'], 'tls': self.connection.version(),
                                    'mensagem': 'Conta de demonstração; sem dados bancários reais.'}
            self.reply(200, response)
        except EnrollmentError as exc:
            LOG.warning('PEDIDO_RECUSADO status=%s', exc.status)
            self.reply(exc.status, {'erro': str(exc)})
        except (ValueError, UnicodeError):
            self.reply(400, {'erro': 'JSON ou valor inválido.'})
        except Exception:
            LOG.exception('PEDIDO_FALHOU')
            self.reply(500, {'erro': 'Falha interna. Consulte os logs locais.'})

    def do_POST(self):
        self.handle_api(True)

    def do_GET(self):
        self.handle_api(False)

    def log_request(self, code='-', size='-'):
        path = getattr(self, 'path', '').split('?', 1)[0]
        if path not in {'/auth/enrollment', '/enroll', '/session', '/account', '/renew', '/logout'}:
            path = '<desconhecido>'
        LOG.info('HTTP_RESPOSTA servico=%s metodo=%s caminho=%s status=%s',
                 'mtls' if self.server.mutual else 'cadastro', self.command, path, code)

    def log_message(self, message, *args):
        # BaseHTTPServer pode incluir a linha de request em erros. Não ecoar entrada livre.
        LOG.warning('HTTP_PROTOCOLO_EVENTO')


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state, port, mutual, attestor=None):
        self.state, self.mutual = state, mutual
        self.attestor = attestor or GoogleAttestation(state)
        self.workers = threading.BoundedSemaphore(8)
        self.context = tls_context(state, mutual)
        super().__init__(('127.0.0.1', port), Handler)

    def process_request(self, request, address):
        if not self.workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, raw, address):
        try:
            self.tls_worker(raw, address)
        finally:
            self.workers.release()

    def tls_worker(self, raw, address):
        # TLS no worker: um cliente lento não bloqueia o accept dos demais.
        raw.settimeout(10)
        try:
            connection = self.context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            LOG.warning('TLS_RECUSADO servico=%s motivo=%s',
                        'mtls' if self.mutual else 'cadastro', getattr(exc, 'reason', type(exc).__name__))
            raw.close()
            return
        LOG.info('TLS_OK servico=%s protocolo=%s cifra=%s',
                 'mtls' if self.mutual else 'cadastro', connection.version(), connection.cipher()[0])
        super().process_request_thread(connection, address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'create-user', 'devices', 'revoke', 'renew', 'test', 'check', 'serve'])
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--enrollment-port', type=int, default=8444)
    parser.add_argument('--account', default='aluno')
    parser.add_argument('--generate-password', action='store_true')
    parser.add_argument('--device')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    os.umask(0o077)
    if args.action == 'test':
        import unittest
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.discover(str(ROOT / 'server'), pattern='test_*.py'))
        raise SystemExit(not result.wasSuccessful())
    initialize(STATE)
    if args.action == 'init':
        print(f'CA e servidor disponíveis em {STATE}; nenhuma chave de cliente foi gerada.')
    elif args.action == 'create-user':
        import getpass
        password = secrets.token_urlsafe(18) if args.generate_password else getpass.getpass('Senha (12–128 caracteres): ')
        provision = auth.create_user(STATE, args.account, password)
        if args.generate_password:
            provision['password'] = password
        target = STATE / ('provision-' + args.account + '.json')
        with target.open('x') as stream:
            json.dump(provision, stream, indent=2)
        target.chmod(0o600)
        print(f'Usuário criado. Dados privados de provisionamento: {target}')
        print('Importe o segredo TOTP no autenticador. Esse arquivo não vai para o Git.')
    elif args.action == 'renew':
        renew_server(STATE)
        print('Certificado do servidor renovado. Reinicie o servidor. Clientes mantêm sua validade própria.')
    elif args.action == 'devices':
        with closing(database(STATE)) as db:
            for row in db.execute('SELECT id,account,active,attested FROM devices ORDER BY rowid'):
                print(json.dumps(dict(row)))
    elif args.action == 'revoke':
        with closing(database(STATE)) as db, db:
            changed = db.execute('UPDATE devices SET active=0 WHERE id=?', (args.device,)).rowcount
        if not changed:
            parser.error('Informe --device com um identificador de devices.')
        print('Identidade revogada; a API recusará a próxima requisição.')
    elif args.action == 'check':
        GoogleAttestation(STATE).preflight()
        tls_context(STATE, True)
        print('Configuração local pronta.')
    else:
        attestor = GoogleAttestation(STATE)
        attestor.preflight()
        with ExitStack() as stack:
            enrollment = stack.enter_context(Server(STATE, args.enrollment_port, False, attestor))
            api = stack.enter_context(Server(STATE, args.port, True, attestor))
            thread = threading.Thread(target=enrollment.serve_forever, daemon=True)
            thread.start()
            LOG.info('SERVIDOR_INICIADO cadastro=https://localhost:%s/enroll api=https://localhost:%s/account',
                     args.enrollment_port, args.port)
            try:
                api.serve_forever()
            except KeyboardInterrupt:
                LOG.info('SERVIDOR_ENCERRADO')
            finally:
                enrollment.shutdown()
                thread.join(timeout=5)


if __name__ == '__main__':
    main()
