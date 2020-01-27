#!/usr/bin/env python3

from math import ceil

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.backends import default_backend
from .byte_data import ByteData


class AesECB:
    def __init__(self, data):
        self._data = data
        self.backend = default_backend()

    def encrypt(self, key):
        cipher = Cipher(AES(key.get_data()), ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(self._data.get_data())

        return ByteData(ciphertext)

    def decrypt(self, key):
        cipher = Cipher(AES(key.get_data()), ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        cleartext = decryptor.update(self._data.get_data())

        return ByteData(cleartext)

    def verify_ecb_mode(self, key_size):
        seen = dict()

        for num in range(0, len(self._data), key_size):
            block = self._data[num:num+key_size].get_data()
            if block not in seen:
                seen[block] = 1
            else:
                seen[block] += 1

        if len(seen) < (len(self._data) / key_size):
            return True
        return False


class AesCBC:
    def __init__(self, data):
        self._data = data

    def encrypt(self, key, iv=0):
        key_size = len(key)
        if iv == 0:
            iv = ByteData(bytes(key_size))
        prev_block = iv

        padded_cleartext = self._data.pkcs7_pad(key_size)
        cipher = ByteData()

        for index in range(0, len(padded_cleartext), key_size):
            block = padded_cleartext[index:index+key_size]
            xored_block = AesECB(block ^ prev_block)
            cipher_block = xored_block.encrypt(key)
            cipher += cipher_block
            prev_block = cipher_block

        return cipher

    def decrypt(self, key, iv=0):
        key_size = len(key)
        if iv == 0:
            iv = ByteData(bytes(key_size))
        prev_block = iv

        cleartext = ByteData()

        for index in range(0, len(self._data), key_size):
            block = self._data[index:index+key_size]
            aes_cipher = AesECB(block)
            xored_block = aes_cipher.decrypt(key)
            cleartext += xored_block ^ prev_block
            prev_block = block

        return cleartext


class AesCTR:
    def __init__(self, data, nonce=0):
        self._data = data
        self._nonce = nonce

    def _get_int_little_endian(self, number):
        return ByteData(int.to_bytes(number, length=8, byteorder='little'))

    def encrypt(self, key):
        key_size = len(key)
        stream = ByteData()

        for num in range(ceil(len(self._data)/key_size)):
            stream_block = AesECB(self._get_int_little_endian(self._nonce) +
                                  self._get_int_little_endian(num))
            stream += stream_block.encrypt(key)

        cipher = self._data ^ stream[:len(self._data)]

        return cipher

    def decrypt(self, key):
        cleartext = self.encrypt(key)
        return cleartext
