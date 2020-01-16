#!/usr/bin/env python3
import string

from crypto_tools import AesECB


class BreakECBEncryption:
    def __init__(self, backend):
        self._backend = backend
        self._find_cipher_stats()
        self._find_payload_position()

    def _find_cipher_stats(self):
        self.cipher_size = len(self._backend.encrypt(''))
        for num in range(32):
            payload = 'A' * num
            new_cipher_len = len(self._backend.encrypt(payload))
            if new_cipher_len != self.cipher_size:
                self.block_size = new_cipher_len - self.cipher_size
                self.cipher_padding = len(payload) - 1
                break

    def _split_cipher(self, cipher):
        cipher_blocks = list()
        for num in range(0, len(cipher), self.block_size):
            cipher_blocks.append(cipher[num: num+self.block_size])

        return cipher_blocks

    def _find_duplicates(self, cipher_blocks):
        for index in range(len(cipher_blocks)-1):
            if cipher_blocks[index] == cipher_blocks[index+1]:
                return index
        return -100

    def _find_payload_position(self):
        for num in range(2*self.block_size, 3*self.block_size):
            payload = 'A' * num
            new_cipher = self._backend.encrypt(payload)
            cipher_blocks = self._split_cipher(new_cipher)
            duplicate_index = self._find_duplicates(cipher_blocks)
            if duplicate_index >= 0:
                self.payload_position = duplicate_index * self.block_size + (2 * self.block_size - num)
                break

    def _match_byte(self, known_cleartext, match):
        for char in string.printable:
            payload = 'A' * (self.cipher_size - len(known_cleartext) - 1 - self.payload_position) + known_cleartext + char
            complete_cipher = self._backend.encrypt(payload)
            cuttet_cipher = complete_cipher[self.payload_position:self.cipher_size]
            if cuttet_cipher == match:
                return char

    def verify_ecb_mode(self):
        payload = 'A' * self.block_size * 3
        cipher = AesECB(self._backend.encrypt(payload))

        return cipher.verify_ecb_mode(self.block_size)

    def break_ecb(self):
        known_cleartext = ''
        target_bytes = self.cipher_size - self.cipher_padding - self.payload_position
        for num in range(target_bytes):
            payload = 'A' * (self.cipher_size - len(known_cleartext) - 1 - self.payload_position)
            match = self._backend.encrypt(payload)[self.payload_position:self.cipher_size]
            known_cleartext += self._match_byte(known_cleartext, match)

        return known_cleartext
