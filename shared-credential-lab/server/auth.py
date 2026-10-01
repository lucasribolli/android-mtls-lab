"""Senha + TOTP. Nenhum segredo de login é embutido no APK."""
import base64
from contextlib import closing
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet

SESSION_TTL = 900
GRANT_TTL = 300


class Error(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def connect(state):
    db = sqlite3.connect(state / 'shared.db', timeout=15)
    db.row_factory = sqlite3.Row
    return db


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def initialize(state):
    key = state / 'mfa.key'
    if not key.exists():
        # Exclusivo para não sobrescrever outra inicialização concorrente.
        try:
            with key.open('xb') as stream:
                stream.write(Fernet.generate_key())
            key.chmod(0o600)
        except FileExistsError:
            pass
    with closing(connect(state)) as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                account TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                totp_encrypted BLOB NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1);
            CREATE TABLE IF NOT EXISTS auth_limits (
                bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL);
        ''')


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def create_user(state, account, password):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,80}', account):
        raise ValueError('Conta deve conter 1–80 letras ASCII, números, _, ., @ ou -.')
    if not 12 <= len(password) <= 128:
        raise ValueError('Senha deve conter 12–128 caracteres.')
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    salt = secrets.token_bytes(16)
    encrypted = Fernet((state / 'mfa.key').read_bytes()).encrypt(secret.encode())
    with closing(connect(state)) as db, db:
        db.execute('INSERT INTO users(account,salt,password_hash,totp_encrypted) VALUES (?,?,?,?)',
                   (account, salt, password_hash(password, salt), encrypted))
    uri = 'otpauth://totp/' + quote('Shared mTLS Lab:' + account, safe='') + '?' + urlencode({
        'secret': secret, 'issuer': 'Shared mTLS Lab', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
    return {'account': account, 'totp_secret': secret, 'otpauth_uri': uri}


def totp(secret, counter, digits=6):
    value = hmac.digest(base64.b32decode(secret), counter.to_bytes(8, 'big'), 'sha1')
    offset = value[-1] & 15
    number = int.from_bytes(value[offset:offset+4], 'big') & 0x7fffffff
    return str(number % (10**digits)).zfill(digits)


def credentials(state, data, expected_account=None):
    if (not isinstance(data, dict) or set(data) != {'account', 'password', 'otp'}
            or not all(isinstance(v, str) for v in data.values())
            or len(data['account']) > 80 or len(data['password']) > 128
            or not re.fullmatch(r'[0-9]{6}', data['otp'])):
        raise Error(400, 'Envie account, password e otp (seis dígitos).')
    account, password, code = data['account'], data['password'], data['otp']
    current = time.time()
    with closing(connect(state)) as db:
        db.execute('BEGIN IMMEDIATE')
        # Limites locais persistem após reinício. Não são proteção distribuída de produção.
        for bucket, limit in [('all-logins', 30), ('account:' + digest(account), 5)]:
            row = db.execute('SELECT * FROM auth_limits WHERE bucket=?', (bucket,)).fetchone()
            if row and row['until'] > current and row['count'] >= limit:
                db.rollback()
                raise Error(429, 'Muitas tentativas. Aguarde até um minuto.')
        for bucket in ['all-logins', 'account:' + digest(account)]:
            db.execute('''INSERT INTO auth_limits VALUES (?,1,?)
                ON CONFLICT(bucket) DO UPDATE SET
                count=CASE WHEN until<=? THEN 1 ELSE count+1 END,
                until=CASE WHEN until<=? THEN excluded.until ELSE until END''',
                       (bucket, current + 60, current, current))
        user = db.execute('SELECT * FROM users WHERE account=?', (account,)).fetchone()
        computed = password_hash(password, user['salt'] if user else b'\0' * 16)
        valid = hmac.compare_digest(computed, user['password_hash'] if user else b'\0' * 32)
        match = None
        if user:
            secret = Fernet((state / 'mfa.key').read_bytes()).decrypt(user['totp_encrypted']).decode()
            for counter in range(int(current // 30) - 1, int(current // 30) + 2):
                if hmac.compare_digest(totp(secret, counter), code) and counter > user['last_counter']:
                    match = counter
        if not valid or match is None or (expected_account is not None and expected_account != account):
            db.commit()  # Falhas precisam contar, mesmo que a requisição seja recusada.
            raise Error(401, 'Login/MFA inválido ou código já usado. Aguarde um novo TOTP se necessário.')
        db.execute('UPDATE users SET last_counter=? WHERE account=?', (match, account))
        db.execute('DELETE FROM auth_limits WHERE bucket=?', ('account:' + digest(account),))
        db.commit()
    return account
