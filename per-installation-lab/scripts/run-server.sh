#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$repo_dir/server/.venv/bin/python"
server_script="$repo_dir/server/lab.py"
pid_file="$repo_dir/.local/server.pid"
if [[ ! -x "$python_bin" ]]; then
    printf 'Prepare o ambiente Python antes de iniciar o servidor:\n  "%s/scripts/setup-server.sh"\n' "$repo_dir" >&2
    exit 1
fi
# Não encerra um servidor funcional se o ambiente da nova instância estiver incompleto.
if ! "$python_bin" -c 'import cryptography' >/dev/null 2>&1; then
    printf 'Dependências Python ausentes. Execute:\n  "%s/scripts/setup-server.sh"\n' "$repo_dir" >&2
    exit 1
fi
for executable in flock tee; do
    command -v "$executable" >/dev/null || {
        printf 'Comando necessário não encontrado: %s\n' "$executable" >&2
        exit 1
    }
done
# Confere também JVM/verificador, política e TLS antes de encerrar a instância anterior.
"$python_bin" "$server_script" check
mkdir -p "$repo_dir/.local"
# Serializa reinícios simultâneos. O filho não herda este descritor.
exec 9>"$repo_dir/.local/server.lock"
flock 9

# Confere /proc, em vez de confiar em um PID antigo ou matar quem ocupa a porta.
# Também encontra "python lab.py serve" iniciado manualmente dentro de server/.
"$python_bin" - "$server_script" <<'PY'
import os
from pathlib import Path
import re
import select
import signal
import sys

target = Path(sys.argv[1]).resolve()
for process in Path('/proc').iterdir():
    if not process.name.isdecimal():
        continue
    pidfd = None
    try:
        if process.stat().st_uid != os.getuid():
            continue
        # O descritor fixa a identidade do processo mesmo se seu PID for reutilizado.
        pidfd = os.pidfd_open(int(process.name))
        args = (process / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        args = [os.fsdecode(arg) for arg in args]
        if not args or not re.fullmatch(r'python(?:\d+(?:\.\d+)*)?', Path(args[0]).name):
            continue
        index = 1
        while index < len(args) and args[index] in {'-u', '-B', '-E', '-I', '-s', '-S'}:
            index += 1
        if index + 1 >= len(args) or args[index + 1] != 'serve':
            continue
        script = Path(args[index])
        if not script.is_absolute():
            script = (process / 'cwd').resolve() / script
        if script.resolve() != target:
            continue
        print(f'Encerrando instância anterior do laboratório (PID {process.name})…', flush=True)
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        if not select.select([pidfd], [], [], 5)[0]:
            print(f'PID {process.name} não encerrou em 5 s; enviando SIGKILL.', flush=True)
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            if not select.select([pidfd], [], [], 5)[0]:
                raise RuntimeError(f'Não foi possível encerrar o PID {process.name}.')
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        # O processo pode encerrar durante a leitura, ou pertencer a outro usuário.
        continue
    finally:
        if pidfd is not None:
            os.close(pidfd)
PY

server_pid=''
cleanup() {
    trap - EXIT INT TERM HUP
    if [[ -n "$server_pid" ]]; then
        # jobs -pr limita o encerramento ao filho ainda ativo deste shell.
        if [[ "$(jobs -pr)" == "$server_pid" ]]; then
            kill -TERM "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
        flock 9
        # Uma instância substituída não apaga o PID da nova instância.
        if [[ -f "$pid_file" && "$(<"$pid_file")" == "$server_pid" ]]; then
            rm -f -- "$pid_file"
        fi
        flock -u 9
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

"$python_bin" -u "$server_script" serve "$@" 9>&- \
    > >(tee -a "$repo_dir/.local/server.log" 9>&-) 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" > "$pid_file"
printf 'Iniciando servidor (PID %s). Logs: %s/.local/server.log\n' "$server_pid" "$repo_dir"
flock -u 9
wait "$server_pid"
