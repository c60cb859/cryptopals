#!/usr/bin/env python3
from crypto_tools import HexConverter
from crypto_tools import EncryptedCookieGenerator

backend = EncryptedCookieGenerator()


def get_cookie(email, backend):
    cipher = backend.encrypt(email)
    return cipher


if __name__ == '__main__':
    email = 'user@email.com'
    hex_cipher = get_cookie(email, backend).encode(HexConverter())
    print(hex_cipher)
