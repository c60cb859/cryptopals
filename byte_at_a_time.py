#!/usr/bin/env python3
import string
import random

from crypto_tools import ByteData
from crypto_tools import AesECB
from crypto_tools import Base64Converter
from crypto_tools import UTF8Converter


class EncryptionBackend:
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


class BreakECBEncryption:
    def __init__(self, backend):
        self._backend = backend
        self._find_cipher_stats()

    def _find_cipher_stats(self):
        size = 0
        for num in range(32):
            payload = 'A' * num
            cipher_len = len(backend.encrypt(payload))
            if size == 0:
                size = cipher_len
            elif cipher_len != size:
                self.block_size = cipher_len - size
                self.cipher_size = size
                self.cipher_padding = num - 1
                break

    def _build_payload_dict(self, known_cleartext):
        payload_dict = {}
        for char in string.printable:
            payload = 'A' * (self.cipher_size - len(known_cleartext) - 1) + known_cleartext + char
            complete_cipher = self._backend.encrypt(payload)
            cuttet_cipher = complete_cipher[:self.cipher_size]
            payload_dict[cuttet_cipher.get_data()] = payload

        return payload_dict

    def verify_ecb_mode(self):
        payload = 'A' * self.block_size * 2
        cipher = AesECB(backend.encrypt(payload))

        return cipher.verify_ecb_mode(self.block_size)

    def break_ecb(self):
        known_cleartext = ''
        for num in range(self.cipher_size - self.cipher_padding):
            payload_dict = self._build_payload_dict(known_cleartext)
            payload = 'A' * (self.cipher_size - len(known_cleartext) - 1)

            leaking = self._backend.encrypt(payload)[:self.cipher_size]
            known_cleartext += payload_dict[leaking.get_data()][-1]

        return known_cleartext


backend = EncryptionBackend()

break_ecb = BreakECBEncryption(backend)
if break_ecb.verify_ecb_mode():
    print(break_ecb.break_ecb())
