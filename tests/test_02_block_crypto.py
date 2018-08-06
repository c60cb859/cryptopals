#!/bin/python3

import unittest
import crypto_tools.aes_ecb as aes


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = 'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'

        block_size = 20
        cleartext = 'YELLOW SUBMARINE'

        padded_cleartext = aes.padding_pkcs7(block_size, cleartext)

        self.assertEqual(result, padded_cleartext)


if __name__ == '__main__':
    unittest.main()
