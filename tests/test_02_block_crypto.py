#!/bin/python3

import unittest
import crypto_tools.aes_ecb as aes
import crypto_tools.data_conversion as dc


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = 'YELLOW SUBMARINE\x04\x04\x04\x04'

        block_size = 20
        cleartext = 'YELLOW SUBMARINE'
        byte_cleartext = dc.utf8_to_bytes(cleartext)

        byte_padded_cleartext = aes.padding_pkcs7(block_size, byte_cleartext)
        padded_cleartext = dc.bytes_to_utf8(byte_padded_cleartext)

        self.assertEqual(result, padded_cleartext)


if __name__ == '__main__':
    unittest.main()
