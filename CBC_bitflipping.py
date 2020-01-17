#!/usr/bin/env python3
from crypto_tools import CBCBitFlippingAttack

backend = CBCBitFlippingAttack()


def get_cookie(email, backend):
    cipher = backend.encrypt(email)
    return cipher


if __name__ == '__main__':
    user_input = 'test;admin=true'
    cipher = backend.encrypt(user_input)
    cleartext = backend.decrypt(cipher)
    print(cleartext)
