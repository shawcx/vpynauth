
import os
import hashlib
import hmac
import random
import secrets
import time

USERS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users')

# scrypt with 16 MiB / ~50 ms per hash; auth() blocks OpenVPN while it runs
def hash_password(password, n=2**14, r=8, p=1):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p)
    return f'scrypt${n}${r}${p}${salt.hex()}${key.hex()}'

def check_password(password, stored):
    try:
        scheme, n, r, p, salt, key = stored.split('$')
        if scheme != 'scrypt':
            return False
        key  = bytes.fromhex(key)
        test = hashlib.scrypt(password, salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(key))
    except ValueError:
        return False
    return hmac.compare_digest(test, key)

def load_users():
    if not os.path.exists(USERS):
        return {}
    with open(USERS, 'r') as fp:
        return dict(line.strip().split(',',1) for line in fp if line.strip())

class Verify:
    def __init__(self):
        self.users = load_users()

    def auth(self, vars):
        username = vars.get('username')
        password = vars.get('password', '')
        cn       = vars.get('common_name')
        ip       = vars.get('untrusted_ip')
        port     = vars.get('untrusted_port')

        stored = self.users.get(username)
        if not stored:
            time.sleep(random.random() / 2.0)
            return -1

        if cn != username:
            time.sleep(random.random() / 2.0)
            return -1

        # surrogateescape recovers the raw bytes of a password that wasn't valid UTF-8
        if check_password(password.encode('utf-8', 'surrogateescape'), stored):
            print('Connection from:', ip, port, username, flush=True)
            return 0
        else:
            print('Rejection from:', ip, port, username, flush=True)
            return -1
