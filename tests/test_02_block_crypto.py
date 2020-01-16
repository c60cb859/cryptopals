#!/usr/bin/env python3

import unittest
import pytest
from crypto_tools import ByteData
from crypto_tools import UTF8Converter
from crypto_tools import Base64Converter
from crypto_tools import AesECB
from crypto_tools import AesCBC
from crypto_tools import AesOracle
from crypto_tools import ByteAtATimeECBSimple
from crypto_tools import ByteAtATimeECBHarder
from crypto_tools import BreakECBEncryption


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

    def test_ecb_cbc_detection_oracle(self):
        with open('files/7_result.txt') as f:
            data = ByteData(f.read(), UTF8Converter())
        key_size = 16
        test_count = 100

        for num in range(test_count):
            oracle = AesOracle(data)
            cipher = AesECB(oracle.encrypt())
            if cipher.verify_ecb_mode(key_size):
                encryption = 'ECB'
            else:
                encryption = 'CBC'

            self.assertEqual(oracle.encryption, encryption)

    def test_byte_at_a_time_ecb_decryption_simple(self):
        result = ByteData('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaG' +
                          'UgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJ' +
                          'IGp1c3QgZHJvdmUgYnkK', Base64Converter())

        backend = ByteAtATimeECBSimple()
        break_ecb = BreakECBEncryption(backend)
        if break_ecb.verify_ecb_mode():
            cleartext = break_ecb.break_ecb()
        data = ByteData(cleartext, UTF8Converter())

        self.assertEqual(result, data)

    def test_byte_at_a_time_ecb_decryption_harder(self):
        result = ByteData('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaG' +
                          'UgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJ' +
                          'IGp1c3QgZHJvdmUgYnkK', Base64Converter())

        backend = ByteAtATimeECBHarder()
        break_ecb = BreakECBEncryption(backend)
        if break_ecb.verify_ecb_mode():
            cleartext = break_ecb.break_ecb()
        data = ByteData(cleartext, UTF8Converter())

        self.assertEqual(result, data)

    def test_pkcs7_padding_remove_correct(self):
        result = ByteData(b'ICE ICE BABY')
        data = ByteData(b'ICE ICE BABY\x04\x04\x04\x04')

        padded_data = data.pkcs7_pad_remove()

        self.assertEqual(result, padded_data)

    def test_pkcs7_padding_remove_wrong_length(self):
        result = "Data does not have valid pkcs7 padding: b'Y\x07\x07\x07\x07'"
        data = ByteData(b'ICE ICE BABY\x05\x05\x05\x05')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)

    def test_pkcs7_padding_remove_wrong_padding(self):
        result = "Data does not have valid pkcs7 padding: b'\x01\x02\x03\x04'"
        data = ByteData(b'ICE ICE BABY\x01\x02\x03\x04')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)


if __name__ == '__main__':
    unittest.main()
