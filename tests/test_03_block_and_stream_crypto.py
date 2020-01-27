#!/usr/bin/env python3

import unittest
from crypto_tools import ByteData
from crypto_tools import Base64Converter
from crypto_tools import UTF8Converter
from crypto_tools import CBCPaddingOracle
from crypto_tools import BreakCBCEncryption
from crypto_tools import AesCTR


class CryptoChallengeSet3(unittest.TestCase):
    def test_cbc_padding_oracle(self):
        result = ByteData('MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                          Base64Converter())

        backend = CBCPaddingOracle()
        break_cbc = BreakCBCEncryption(backend)
        cleartext_data = break_cbc.break_cbc(result.encode(UTF8Converter()))

        self.assertEqual(result, cleartext_data.pkcs7_pad_remove())

    def test_implement_ctr_mode(self):
        result = ByteData("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
                          UTF8Converter())
        key = ByteData('YELLOW SUBMARINE', UTF8Converter())
        cipher = ByteData('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==',
                          Base64Converter())

        aes = AesCTR(cipher)

        cleartext_data = aes.decrypt(key)

        self.assertEqual(result, cleartext_data)


if __name__ == '__main__':
    unittest.main()
