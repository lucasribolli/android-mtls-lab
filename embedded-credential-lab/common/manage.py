"""Administração LOCAL; não há API de provisionamento nem rota que entregue o P12."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
from backend import auth
from backend.app import initialize as initialize_backend
from common import pki
from common.config import ROOT, STATE, CREDENTIAL_VERSION


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('prepare')
    sub.add_parser('check')
    user = sub.add_parser('create-user')
    user.add_argument('account')
    user.add_argument('--generate-password', action='store_true')
    policy = sub.add_parser('credential')
    policy.add_argument('action', choices=['enable', 'disable'])
    args = parser.parse_args()
    if args.command == 'prepare':
        pki.initialize(STATE)
        pki.check(STATE)
        initialize_backend(STATE)
        pki.prepare_android(ROOT, STATE)
        print('PKI e assets locais prontos. DEXGUARD: NOT AVAILABLE / NOT VALIDATED. RASP: NOT ACTIVE.')
    elif args.command == 'check':
        pki.check(STATE)
        print('PKIs externa/interna válidas.')
    elif args.command == 'create-user':
        # A API valida o nome antes de construir/salvar qualquer caminho de perfil.
        import re
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,80}', args.account):
            parser.error('Nome de conta inválido.')
        target = STATE / ('provision-' + args.account + '.json')
        with target.open('x') as stream:
            target.chmod(0o600)
            try:
                password = secrets.token_urlsafe(18) if args.generate_password else getpass.getpass('Senha (12–128 caracteres): ')
                result = auth.create_user(STATE, args.account, password)
                if args.generate_password:
                    result['password'] = password
                json.dump(result, stream, indent=2)
            except Exception:
                target.unlink()
                raise
        print('Perfil TOTP privado salvo em ' + str(target) + '; não publique nem inclua em logs.')
    elif args.command == 'credential':
        path = STATE / 'gateway-policy.json'
        policy = json.loads(path.read_text())
        entry = policy[pki.fingerprint(pki.load_cert(STATE, 'shared-client'))]
        if entry['version'] != CREDENTIAL_VERSION:
            raise RuntimeError('Geração inesperada na política.')
        entry['enabled'] = args.action == 'enable'
        temp = path.with_suffix('.json.tmp')
        pki.write_private(temp, json.dumps(policy, indent=2).encode())
        temp.replace(path)
        print('Política da geração ' + CREDENTIAL_VERSION + ': ' + args.action + '. Afeta todas as instalações.')


if __name__ == '__main__':
    main()
