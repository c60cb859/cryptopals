#!/usr/bin/env python3
from crypto_tools import HexConverter
from crypto_tools import CBCPaddingOracle

backend = CBCPaddingOracle()

if __name__ == '__main__':
    cipher = backend.encrypt()
    print(cipher.encode(HexConverter()))
