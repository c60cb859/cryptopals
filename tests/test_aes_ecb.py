#!/bin/python3

import unittest
import crypto_tools.aes_ecb as aes
import crypto_tools.data_conversion as dc


class AesEcb(unittest.TestCase):
    def test_pkcs7_10_padding(self):
        block_size = 20
        padding_lenght = 10
        num = block_size - padding_lenght
        padding = '\x0a' * padding_lenght
        result = 'A' * num + padding
        cleartext = 'A' * num

        byte_cleartext = dc.utf8_to_bytes(cleartext)
        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)

    def test_pkcs7_1_padding(self):
        block_size = 20
        padding_lenght = 1
        num = block_size - padding_lenght
        padding = '\x01' * padding_lenght
        result = 'A' * num + padding
        cleartext = 'A' * num

        byte_cleartext = dc.utf8_to_bytes(cleartext)
        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)

    def test_pkcs7_19_padding(self):
        block_size = 20
        padding_lenght = 19
        num = block_size - padding_lenght
        padding = '\x13' * padding_lenght
        result = 'A' * num + padding
        cleartext = 'A' * num

        byte_cleartext = dc.utf8_to_bytes(cleartext)
        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)

    def test_pkcs7_0_padding(self):
        block_size = 20
        padding_lenght = 0
        num = block_size - padding_lenght
        result = 'A' * num
        cleartext = 'A' * num

        byte_cleartext = dc.utf8_to_bytes(cleartext)
        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)

    def test_pkcs7_0_padding_big(self):
        block_size = 20
        padding_lenght = 0
        num = (block_size - padding_lenght) * 2
        result = 'A' * num
        cleartext = 'A' * num

        byte_cleartext = dc.utf8_to_bytes(cleartext)
        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)


if __name__ == '__main__':
    unittest.main()
