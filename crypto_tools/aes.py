#!/usr/bin/env python3

from Crypto.Cipher import AES
from .byte_data import ByteData


class AesECB:
    def __init__(self, data):
        self._data = data

    def encrypt(self, key):
        algrorithm = AES.new(key.get_data(), AES.MODE_ECB)
        cipher = ByteData(algrorithm.encrypt(self._data.get_data()))

        return cipher

    def decrypt(self, key):
        algrorithm = AES.new(key.get_data(), AES.MODE_ECB)
        cleartext = ByteData(algrorithm.decrypt(self._data.get_data()))

        return cleartext

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
