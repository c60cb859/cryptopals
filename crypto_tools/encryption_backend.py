#!/usr/bin/env python3
import string
import random

from .byte_data import ByteData
from .aes import AesECB
from .data_conversion import Base64Converter
from .data_conversion import UTF8Converter


class EncryptionBackend:
    def __init__(self):
        pass

    def encrypt(self, cleartext):
        pass


class ByteAtATimeECBSimple(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_printable_key()
        self._text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' +\
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        self._data = ByteData(self._text, Base64Converter())

    def _generate_printable_key(self):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(self.key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

    def encrypt(self, cleartext):
        known_data = ByteData(cleartext, UTF8Converter())
        cleartext_data = known_data + self._data

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher
