#!/usr/bin/env python3
from .byte_data import ByteData
from .data_conversion import IntConverter


class BreakCBCEncryption:
    def __init__(self, backend):
        self._backend = backend
        self._block_size = 16

    def _split_cipher(self, cipher):
        blocks = list()
        for size in range(0, len(cipher), self._block_size):
            blocks.append(cipher[size:size+self._block_size])

        return blocks

    def _break_block(self, block):
        intermiedate = ByteData(b'\x00'*self._block_size)

        for index in range(self._block_size):
            key = ByteData(index+1, IntConverter())
            padding = intermiedate.repeating_key_xor(key)

            for byte in range(256):
                padding[self._block_size-(index+1)] = byte
                if self._backend.decrypt(padding+block):
                    break
            intermiedate[self._block_size-(index+1)] = byte ^ (index+1)
        return intermiedate

    def break_cbc(self, cleatext=''):
        cipher, iv = self._backend.encrypt(cleatext)
        blocks = [iv]
        blocks += self._split_cipher(cipher)
        cleartext_data = ByteData()

        for num in range(1, len(blocks)):
            intermiedate = self._break_block(blocks[num])
            cleartext_data += blocks[num-1] ^ intermiedate

        return cleartext_data
