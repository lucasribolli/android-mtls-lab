"""HTTP limitado e TLS no worker. Servidor de laboratório, não proxy de produção."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import signal
import socket
import ssl
import threading

LOG = logging.getLogger('embedded-lab')
MAX_BODY = 16384


class Error(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def exactly_one(headers, name, required=False):
    values = headers.get_all(name, [])
    if len(values) > 1 or (required and len(values) != 1):
        raise Error(400, 'Header obrigatório ausente ou duplicado.')
    return values[0] if values else ''


class Handler(BaseHTTPRequestHandler):
    server_version = 'EmbeddedLab/0.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def body(self):
        if self.headers.get_all('Transfer-Encoding'):
            raise Error(400, 'Transfer-Encoding não suportado.')
        length = exactly_one(self.headers, 'Content-Length')
        if self.command == 'GET':
            if length not in {'', '0'}:
                raise Error(400, 'GET não aceita corpo.')
            return None
        if not length.isdecimal():
            raise Error(400, 'Content-Length inválido.')
        size = int(length)
        if not 0 < size <= MAX_BODY:
            raise Error(413, 'Corpo excede o limite.')
        if self.headers.get_content_type() != 'application/json':
            raise Error(415, 'Use application/json.')
        body = self.rfile.read(size)
        if len(body) != size:
            raise Error(400, 'Corpo incompleto.')
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError) as error:
            raise Error(400, 'JSON inválido.') from error
        if not isinstance(data, dict):
            raise Error(400, 'Envie um objeto JSON.')
        return data

    def respond(self):
        try:
            # Não aceitamos framing/headers ambíguos, nem espelhamos headers externos.
            exactly_one(self.headers, 'Host', required=True)
            authorization = exactly_one(self.headers, 'Authorization')
            if len(authorization) > 512:
                raise Error(400, 'Authorization grande demais.')
            data = self.body()  # Consumir corpo pequeno válido antes de responder 404 (evita TCP RST).
            if '?' in self.path or self.path not in self.server.app.paths:
                raise Error(404, 'Endpoint não disponível neste serviço.')
            status, result = self.server.app.handle(self, data)
        except Error as error:
            status, result = error.status, {'error': str(error)}
        except (socket.timeout, ConnectionError):
            return
        except Exception as error:
            LOG.error('ERRO_INTERNO service=%s type=%s', self.server.label, type(error).__name__)
            status, result = 500, {'error': 'Falha interna do laboratório.'}
        try:
            body = json.dumps(result, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        LOG.info('HTTP service=%s method=%s path=%s status=%s', self.server.label, self.command, self.path, status)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, context, app, label):
        self.context, self.app, self.label = context, app, label
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

    def process_request_thread(self, raw, address):
        try:
            raw.settimeout(10)
            with self.context.wrap_socket(raw, server_side=True) as tls:
                self.finish_request(tls, address)
        except (OSError, ssl.SSLError):
            LOG.info('TLS_RECUSADO_OU_CONEXAO_ENCERRADA service=%s', self.label)
        finally:
            self.shutdown_request(raw)
            self.slots.release()


def serve(servers):
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            LOG.info('LISTENER service=%s address=%s port=%s', server.label, *server.server_address)
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
