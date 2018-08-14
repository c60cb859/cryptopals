#!/usr/bin/env python3

import unittest
from crypto_tools import ByteData
from crypto_tools import UTF8Converter
from crypto_tools import Base64Converter
from crypto_tools import AesCBC


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = ByteData(b'YELLOW SUBMARINE\x04\x04\x04\x04')

        block_size = 20
        data = ByteData(b'YELLOW SUBMARINE')

        padded_data = data.pkcs7_pad(block_size)

        self.assertEqual(result, padded_data)

    def test_implement_cbc_mode(self):
        with open('files/7_result.txt') as f:
            result = f.read()

        with open('files/10.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        key = ByteData('YELLOW SUBMARINE', UTF8Converter())
        data = ByteData(base64_cipher_text, Base64Converter())
        cipher = AesCBC(data)

        cleartext = cipher.decrypt(key)

        self.assertEqual(result, cleartext.encode(UTF8Converter()))


if __name__ == '__main__':
    unittest.main()
