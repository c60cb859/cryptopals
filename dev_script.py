#!/usr/bin/env python3
from crypto_tools import ByteData
from crypto_tools import CBCPaddingOracle
from crypto_tools import IntConverter


class BreakECBCncryption:
    def __init__(self, backend):
        self._backend = backend
        self._block_size = 16

    def break_cbc(self):
        pass


if __name__ == '__main__':
    backend = CBCPaddingOracle()
    cleatext = 'x'*16 + 'abcdefghijklmn'
    cipher = backend.encrypt(cleatext)

    first_block = cipher[:16]
    last_block = cipher[-16:]
    I2 = ByteData(b'\x00'*16)

    for count in range(16):
        key = ByteData(count+1, IntConverter())
        pad = I2.repeating_key_xor(key)
        for num in range(256):
            pad[16-(count+1)] = num
            if backend.decrypt(pad+last_block):
                break
        I2[16-(count+1)] = num ^ (count+1)

    print(I2.get_data())
    cleartext_byte = ByteData(I2) ^ first_block
    print(cleartext_byte.get_data())
