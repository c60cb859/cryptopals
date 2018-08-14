#!/bin/python3

import unittest
from crypto_tools import ByteData


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = ByteData(b'YELLOW SUBMARINE\x04\x04\x04\x04')

        block_size = 20
        data = ByteData(b'YELLOW SUBMARINE')

        padded_data = data.pkcs7_pad(block_size)

        self.assertEqual(result, padded_data)


if __name__ == '__main__':
    unittest.main()
