#!/usr/bin/env python3
import string
import random

from .aes import AesECB
from .aes import AesCBC
from .byte_data import ByteData
from .data_conversion import UTF8Converter


class AesOracle:
    def __init__(self, data):
        self._data = data
        self.key_size = 16
        self.encryption = None

        self.key = self._generate_printable_key()
        self._front_padding = self._generate_random_padding()
        self._back_padding = self._generate_random_padding()

    def _generate_printable_key(self):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(self.key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

    def _generate_random_padding(self):
        padding = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(random.randint(5,10)):
            padding += random.choice(printable_char)

        return ByteData(padding, UTF8Converter())

    def _generate_random_iv(self):
        iv = bytearray()
        for num in range(self.key_size):
            iv += bytes([random.randint(0, 255)])

        return ByteData(iv)

    def _encrypt_ecb(self):
        data = self._front_padding + self._data + self._back_padding

        cleartext = AesECB(data.pkcs7_pad(self.key_size))
        ciper = cleartext.encrypt(self.key)

        return ciper

    def _encrypt_cbc(self):
        data = self._front_padding + self._data + self._back_padding
        iv = self._generate_random_iv()

        cleartext = AesCBC(data.pkcs7_pad(self.key_size))
        ciper = cleartext.encrypt(self.key, iv)

        return ciper

    def encrypt(self):
        if random.randint(0, 1):
            self.encryption = 'ECB'
            return self._encrypt_ecb()
        else:
            self.encryption = 'CBC'
            return self._encrypt_cbc()
