"""Simulação explícita do emissor/verificador RASP. Não detecta root, Frida ou malware."""
import base64
import hashlib
import hmac
import json
import secrets
import time

from auth import Error


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def decode(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


class DemoRasp:
    mode = 'DEMO'

    def __init__(self, state):
        self.state = state

    def issue(self, grant, decision):
        if decision not in {'approved', 'blocked'}:
            raise Error(503, 'Simulador RASP indisponível; a entrega permanece bloqueada.')
        stamp = int(time.time())
        claims = {'aud': 'shared-mtls-lab/provision', 'mode': self.mode,
                  'grant': grant['digest'], 'account': grant['account'], 'nonce': grant['challenge'],
                  'decision': decision, 'iat': stamp, 'exp': stamp + 60,
                  'jti': secrets.token_urlsafe(16)}
        payload = encode(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode())
        signature = encode(hmac.digest((self.state / 'rasp-demo.key').read_bytes(), payload.encode(), 'sha256'))
        return payload + '.' + signature

    def verify(self, evidence, grant):
        if not isinstance(evidence, str) or len(evidence) > 4096:
            raise Error(403, 'Evidência RASP inválida.')
        try:
            payload, supplied = evidence.split('.')
            expected = hmac.digest((self.state / 'rasp-demo.key').read_bytes(), payload.encode(), 'sha256')
            if not hmac.compare_digest(decode(supplied), expected):
                raise ValueError('Assinatura inválida')
            claims = json.loads(decode(payload))
            if (claims['aud'] != 'shared-mtls-lab/provision' or claims['mode'] != 'DEMO'
                    or claims['grant'] != grant['digest'] or claims['account'] != grant['account']
                    or claims['nonce'] != grant['challenge']
                    or type(claims['iat']) is not int or type(claims['exp']) is not int
                    or not claims['iat'] <= time.time() < claims['exp']
                    or not 0 < claims['exp'] - claims['iat'] <= 60):
                raise ValueError('Vínculo/prazo inválido')
        except (ValueError, KeyError, TypeError) as error:
            raise Error(403, 'Evidência RASP ausente, adulterada, expirada ou de outro pedido.') from error
        if claims['decision'] != 'approved':
            raise Error(403, 'RASP SIMULADO bloqueou a entrega. Isso não é uma detecção real no aparelho.')
        return claims


class BankRaspNotIntegrated:
    mode = 'BANK_NOT_INTEGRATED'

    def issue(self, grant, decision):
        raise Error(503, 'O SDK/serviço RASP do banco ainda não foi integrado.')

    def verify(self, evidence, grant):
        raise Error(503, 'O verificador RASP do banco ainda não foi integrado; entrega bloqueada.')
