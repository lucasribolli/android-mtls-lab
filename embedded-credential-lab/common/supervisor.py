"""Inicia e supervisiona APENAS os dois filhos deste laboratório; Ctrl+C encerra ambos."""
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from common import pki
from common.config import ROOT, STATE, PORTS


def main():
    os.umask(0o077)
    pki.check(STATE)
    # Falhar em conflito é preferível a encerrar processos de outros labs/usuários.
    for port in PORTS.values():
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    children, logs = [], []
    pid_path = ROOT / '.local/lab.pid'
    pid_path.write_text(str(os.getpid()))
    try:
        for label, module, extra in [('backend', 'backend.app', []), ('gateway', 'gateway.app', ['--diagnostics'])]:
            log = (ROOT / '.local' / (label + '.log')).open('ab', buffering=0)
            logs.append(log)
            child = subprocess.Popen([sys.executable, '-u', '-m', module, *extra], cwd=ROOT,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            children.append(child)
            print(f'{label}: PID {child.pid}; log .local/{label}.log', flush=True)
        print('Gateway público local :8643; health/pins :8644–8646; backend interno mTLS :8650.', flush=True)
        print('Ctrl+C encerra estes dois processos. Nenhum outro laboratório será encerrado.', flush=True)
        while not stop.wait(0.25):
            if any(child.poll() is not None for child in children):
                raise RuntimeError('Um serviço terminou; consulte os logs. Encerrando o outro serviço.')
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()
        if pid_path.exists() and pid_path.read_text() == str(os.getpid()):
            pid_path.unlink()


if __name__ == '__main__':
    main()
