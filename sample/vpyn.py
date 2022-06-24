
import sys
import os
import crypt
import random
import time

class Verify:
    def __init__(self):
        users = open('users', 'r').readlines()
        self.users = dict(user.strip().split(',',1) for user in users)

    def auth(self, vars):
        vars = dict(v.split('=',1) for v in vars)

        username = vars.get('username')
        password = vars.get('password')
        cn       = vars.get('common_name')
        ip       = vars.get('untrusted_ip')
        port     = vars.get('untrusted_port')

        salt = self.users.get(username)
        if not salt:
            time.sleep(random.random() / 2.0)
            return -1

        if cn != username:
            time.sleep(random.random() / 2.0)
            return -1

        test = crypt.crypt(password, salt)

        if test == salt:
            print('Connection from:', ip, port, username)
            return 0
        else:
            print('Rejection from:', ip, port, username)
            return -1

verify = Verify()
