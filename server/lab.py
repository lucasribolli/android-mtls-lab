#!/usr/bin/env python3
"""Cadastro HTTPS + API mTLS com identidade gerada no Android Keystore."""
import argparse
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
import hashlib
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

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local' / 'bank'
LOG = logging.getLogger('mtls-lab')
PEM = serialization.Encoding.PEM
MAX_BODY = 16384


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
    (state / 'bank.db').chmod(0o600)


def database(state):
    db = sqlite3.connect(state / 'bank.db', timeout=10)
    db.row_factory = sqlite3.Row
    return db


def new_token(state, account, ttl=600):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,80}', account):
        raise ValueError('Conta: use de 1 a 80 letras ASCII, números, _, ., @ ou -.')
    if not 1 <= ttl <= 900:
        raise ValueError('Validade do token deve estar entre 1 e 900 segundos.')
    token = secrets.token_urlsafe(24)
    with closing(database(state)) as db, db:
        db.execute('INSERT INTO tokens(digest,account,expires) VALUES (?,?,?)',
                   (hashlib.sha256(token.encode()).hexdigest(), account, time.time() + ttl))
    return token


class EnrollmentError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def enroll(state, token, csr_pem):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32}', token):
        raise EnrollmentError(401, 'Token ausente, inválido ou expirado.')
    if not isinstance(csr_pem, str) or len(csr_pem) > MAX_BODY:
        raise EnrollmentError(400, 'CSR inválido.')
    digest = hashlib.sha256(csr_pem.encode()).hexdigest()
    # A transação serializa consumo do token e emissão. Repetir o mesmo pedido
    # recupera o mesmo certificado se a resposta HTTPS se perder, sem emitir outro.
    with closing(database(state)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        grant = db.execute('SELECT * FROM tokens WHERE digest=?',
                           (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if grant is None or grant['expires'] <= time.time():
            raise EnrollmentError(401, 'Token ausente, inválido ou expirado.')
        if grant['device_id']:
            if grant['csr_digest'] != digest:
                raise EnrollmentError(409, 'Token já utilizado para outro pedido.')
            record = db.execute('SELECT * FROM devices WHERE id=?', (grant['device_id'],)).fetchone()
            if not record['active']:
                raise EnrollmentError(403, 'Identidade revogada.')
            return dict(record)
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            public = csr.public_key()
            if not (isinstance(public, rsa.RSAPublicKey) and public.key_size == 2048
                    and public.public_numbers().e == 65537
                    and csr.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256
                    and csr.is_signature_valid):
                raise ValueError('Assinatura ou algoritmo não permitido')
        except (ValueError, TypeError, x509.InvalidVersion) as exc:
            raise EnrollmentError(400, 'CSR requer RSA-2048 e assinatura SHA256withRSA válida.') from exc
        device_id = str(uuid.uuid4())
        ca, ca_key = load_ca(state)
        # Subject/extensões do CSR são ignorados: a política e a conta vêm do banco.
        cert = leaf_certificate(public, device_id, ca, ca_key, ExtendedKeyUsageOID.CLIENT_AUTH)
        record = {'id': device_id, 'account': grant['account'], 'fingerprint': fingerprint(cert),
                  'certificate': cert.public_bytes(PEM).decode(), 'active': 1}
        db.execute('INSERT INTO devices(id,account,fingerprint,certificate) VALUES (?,?,?,?)',
                   (device_id, record['account'], record['fingerprint'], record['certificate']))
        db.execute('UPDATE tokens SET csr_digest=?,device_id=? WHERE digest=?',
                   (digest, device_id, grant['digest']))
        LOG.info('CADASTRO_EMITIDO dispositivo=%s conta=%s', device_id, grant['account'])
        return record


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

    def do_POST(self):
        if self.server.mutual or self.path != '/enroll':
            return self.reply(404, {'erro': 'Rota inexistente.'})
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
                raise EnrollmentError(400, 'Content-Length único obrigatório; sem Transfer-Encoding.')
            try:
                length = int(lengths[0])
            except ValueError:
                raise EnrollmentError(400, 'Content-Length inválido.')
            if not 0 < length <= MAX_BODY:
                raise EnrollmentError(413, 'Pedido excede o limite de 16 KiB.')
            if self.headers.get_content_type() != 'application/json':
                raise EnrollmentError(415, 'Use application/json.')
            auth = self.headers.get('Authorization', '')
            token = auth[7:] if auth.startswith('Bearer ') else ''
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or set(data) != {'csr'}:
                raise EnrollmentError(400, 'Envie apenas o campo csr.')
            record = enroll(self.server.state, token, data['csr'])
            self.reply(200, {'device_id': record['id'], 'account': record['account'],
                             'certificate': record['certificate'],
                             'ca': (self.server.state / 'ca.crt').read_text()})
        except EnrollmentError as exc:
            LOG.warning('CADASTRO_RECUSADO status=%s', exc.status)
            self.reply(exc.status, {'erro': str(exc)})
        except (ValueError, UnicodeError):
            self.reply(400, {'erro': 'JSON inválido.'})
        except Exception:
            LOG.exception('CADASTRO_FALHOU')
            self.reply(500, {'erro': 'Não foi possível emitir o certificado.'})

    def do_GET(self):
        if not self.server.mutual or self.path != '/account':
            return self.reply(404, {'erro': 'Rota inexistente.'})
        cert = x509.load_der_x509_certificate(self.connection.getpeercert(binary_form=True))
        with closing(database(self.server.state)) as db:
            device = db.execute('SELECT * FROM devices WHERE fingerprint=? AND active=1',
                                (fingerprint(cert),)).fetchone()
        if device is None:
            return self.reply(403, {'erro': 'Identidade não cadastrada ou revogada.'})
        self.reply(200, {'mtls': True, 'account': device['account'], 'device_id': device['id'],
                         'tls': self.connection.version(), 'mensagem': 'Conta de demonstração; sem dados bancários reais.'})

    def log_request(self, code='-', size='-'):
        # Nunca registrar Authorization, CSR, corpos ou query strings.
        LOG.info('HTTP_RESPOSTA servico=%s metodo=%s caminho=%r status=%s',
                 'mtls' if self.server.mutual else 'cadastro', self.command,
                 getattr(self, 'path', '').split('?', 1)[0], code)

    def log_message(self, message, *args):
        LOG.warning('HTTP_EVENTO mensagem=%r', message % args)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state, port, mutual):
        self.state, self.mutual = state, mutual
        self.context = tls_context(state, mutual)
        super().__init__(('127.0.0.1', port), Handler)

    def process_request_thread(self, raw, address):
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
    parser.add_argument('action', choices=['init', 'token', 'devices', 'revoke', 'renew', 'test', 'serve'])
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--enrollment-port', type=int, default=8444)
    parser.add_argument('--account', default='aluno')
    parser.add_argument('--ttl', type=int, default=600)
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
    elif args.action == 'token':
        print(new_token(STATE, args.account, args.ttl))
    elif args.action == 'renew':
        renew_server(STATE)
        print('Certificado do servidor renovado. Reinicie o servidor. Clientes mantêm sua validade própria.')
    elif args.action == 'devices':
        with closing(database(STATE)) as db:
            for row in db.execute('SELECT id,account,active FROM devices ORDER BY rowid'):
                print(json.dumps(dict(row)))
    elif args.action == 'revoke':
        with closing(database(STATE)) as db, db:
            changed = db.execute('UPDATE devices SET active=0 WHERE id=?', (args.device,)).rowcount
        if not changed:
            parser.error('Informe --device com um identificador de devices.')
        print('Identidade revogada; a API recusará a próxima requisição.')
    else:
        with ExitStack() as stack:
            enrollment = stack.enter_context(Server(STATE, args.enrollment_port, False))
            api = stack.enter_context(Server(STATE, args.port, True))
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
