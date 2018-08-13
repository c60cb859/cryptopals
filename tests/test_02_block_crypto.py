#!/bin/python3

import unittest
import crypto_tools.aes_ecb as aes

from crypto_tools import UTF8Converter


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = 'YELLOW SUBMARINE\x04\x04\x04\x04'

        block_size = 20
        cleartext = 'YELLOW SUBMARINE'
        byte_cleartext = UTF8Converter().decode(cleartext)

        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = UTF8Converter().encode(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)


if __name__ == '__main__':
    unittest.main()
