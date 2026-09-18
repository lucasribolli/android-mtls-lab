#!/usr/bin/env python3
"""Primeiro laboratório mTLS: Python padrão + OpenSSL, sem pacotes pip."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local' / 'certs'


def openssl(folder, *args):
    result = subprocess.run(['openssl', *args], cwd=folder, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)


def generate():
    """Cria uma CA do laboratório, servidor, cliente e cliente de uma outra CA."""
    if (STATE / 'ready').is_file():
        return
    if STATE.exists():
        raise RuntimeError(f'Diretório incompleto já existe: {STATE}; preserve-o e confira o conteúdo.')
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mtls-build-', dir=STATE.parent) as temp:
        folder = Path(temp)
        for name in ['ca', 'other-ca']:
            openssl(folder, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                    '-sha256', '-days', '30', '-subj', f'/CN=MTLS LAB {name}',
                    '-keyout', f'{name}.key', '-out', f'{name}.crt',
                    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                    '-addext', 'subjectKeyIdentifier=hash')
        for name, ca, purpose, cn in [
            ('server', 'ca', 'serverAuth', 'localhost'),
            ('client', 'ca', 'clientAuth', 'android-lab'),
            ('other-client', 'other-ca', 'clientAuth', 'untrusted-client'),
        ]:
            openssl(folder, 'req', '-new', '-newkey', 'rsa:2048', '-noenc',
                    '-subj', f'/CN={cn}', '-keyout', f'{name}.key', '-out', f'{name}.csr')
            extensions = ('basicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          f'extendedKeyUsage={purpose}\n'
                          'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
            if name == 'server':
                extensions += 'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
            (folder / f'{name}.ext').write_text(extensions)
            openssl(folder, 'x509', '-req', '-in', f'{name}.csr', '-CA', f'{ca}.crt',
                    '-CAkey', f'{ca}.key', '-set_serial', str(int.from_bytes(os.urandom(16), 'big') or 1),
                    '-days', '7', '-sha256', '-extfile', f'{name}.ext', '-out', f'{name}.crt')
        # Identidade para importação manual no Android; senha pública de laboratório.
        openssl(folder, 'pkcs12', '-export', '-inkey', 'client.key', '-in', 'client.crt',
                '-certfile', 'ca.crt', '-name', 'android-lab', '-out', 'client.p12',
                '-passout', 'pass:lab-android')
        for file in folder.iterdir():
            file.chmod(0o600)
        (folder / 'ready').write_text('Certificados locais de laboratório; folhas válidas por 7 dias.\n')
        folder.rename(STATE)
    print(f'Certificados de laboratório criados em {STATE}', flush=True)


def server_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(STATE / 'server.crt', STATE / 'server.key')
    context.load_verify_locations(cafile=STATE / 'ca.crt')
    context.verify_mode = ssl.CERT_REQUIRED  # Exige certificado de cliente válido.
    return context


def client_context(identity='client', ca='ca'):
    context = ssl.create_default_context(cafile=STATE / f'{ca}.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if identity:
        context.load_cert_chain(STATE / f'{identity}.crt', STATE / f'{identity}.key')
    return context


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        cert = self.connection.getpeercert()
        subject = dict(item for rdn in cert['subject'] for item in rdn)
        body = json.dumps({'mtls': True, 'cliente': subject.get('commonName'),
                           'tls': self.connection.version()}).encode() + b'\n'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port):
        self.context = server_context()
        super().__init__(('127.0.0.1', port), Handler)

    def get_request(self):
        raw, address = self.socket.accept()
        raw.settimeout(5)
        try:
            return self.context.wrap_socket(raw, server_side=True), address
        except Exception:
            raw.close()
            raise


def request(port, context, hostname='localhost'):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            connection.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            data = b''
            while chunk := connection.recv(16384):
                data += chunk
            header, body = data.split(b'\r\n\r\n', 1)
            if not header.startswith(b'HTTP/1.0 200'):
                raise RuntimeError('Resposta HTTP inesperada')
            return json.loads(body)


def test():
    with Server(0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            result = request(port, client_context())
            if result['cliente'] != 'android-lab' or result['mtls'] is not True:
                raise RuntimeError('Identidade inesperada no teste positivo')
            print(f'PASSOU: certificado válido → HTTP 200 ({result["tls"]})')
            cases = [
                ('sem certificado de cliente', None, 'ca', 'localhost',
                 {'TLSV13_ALERT_CERTIFICATE_REQUIRED', 'SSLV3_ALERT_HANDSHAKE_FAILURE'}),
                ('cliente emitido por outra CA', 'other-client', 'ca', 'localhost',
                 {'TLSV1_ALERT_UNKNOWN_CA'}),
                ('cliente não confia na CA do servidor', 'client', 'other-ca', 'localhost',
                 {'CERTIFICATE_VERIFY_FAILED'}),
                ('nome do servidor incorreto', 'client', 'ca', 'wrong.invalid',
                 {'CERTIFICATE_VERIFY_FAILED'}),
            ]
            for label, identity, ca, hostname, expected in cases:
                try:
                    request(port, client_context(identity, ca), hostname)
                except ssl.SSLError as exc:
                    if exc.reason not in expected:
                        raise RuntimeError(f'Falha TLS inesperada em {label}: {exc}') from exc
                    if hostname == 'wrong.invalid' and getattr(exc, 'verify_code', None) != 62:
                        raise RuntimeError('A falha não foi por hostname') from exc
                    detail = getattr(exc, 'verify_message', None) or exc.reason
                    print(f'PASSOU: {label} → recusado ({detail})')
                else:
                    raise RuntimeError(f'Conexão deveria ter sido recusada: {label}')
        finally:
            server.shutdown()
            thread.join(timeout=5)
    print('5/5 cenários confirmados. Servidor de teste encerrado.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'test', 'serve'])
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    os.umask(0o077)
    generate()
    if args.action == 'init':
        print(f'Certificados disponíveis: {STATE}')
    elif args.action == 'test':
        test()
    else:
        with Server(args.port) as server:
            print(f'Servidor mTLS em https://localhost:{args.port} — Ctrl+C para parar.', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == '__main__':
    main()
