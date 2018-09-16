#!/usr/bin/env python3
import string

from crypto_tools import AesECB


class BreakECBEncryption:
    def __init__(self, backend):
        self._backend = backend
        self._find_cipher_stats()

    def _find_cipher_stats(self):
        self.cipher_size = len(self._backend.encrypt(''))
        for num in range(32):
            payload = 'A' * num
            new_cipher_len = len(self._backend.encrypt(payload))
            if new_cipher_len != self.cipher_size:
                self.block_size = new_cipher_len - self.cipher_size
                self.cipher_padding = len(payload) - 1
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
        cipher = AesECB(self._backend.encrypt(payload))

        return cipher.verify_ecb_mode(self.block_size)

    def break_ecb(self):
        known_cleartext = ''
        for num in range(self.cipher_size - self.cipher_padding):
            payload_dict = self._build_payload_dict(known_cleartext)
            payload = 'A' * (self.cipher_size - len(known_cleartext) - 1)

            leaking = self._backend.encrypt(payload)[:self.cipher_size]
            known_cleartext += payload_dict[leaking.get_data()][-1]

        return known_cleartext
