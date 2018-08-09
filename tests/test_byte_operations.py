#!/bin/python3

import unittest
import crypto_tools.byte_operations as bo

from crypto_tools.data_conversion import HexConverter
from crypto_tools.data_conversion import UTF8Converter


class ByteOperations(unittest.TestCase):
    def test_fixed_xor(self):
        result = bytes([0xbc])
        byte1 = bytes([0x16])
        byte2 = bytes([0xaa])

        xor = bo.fixed_xor(byte1, byte2)

        self.assertEqual(result, xor)

    def test_one_byte_xor(self):
        result = bytes([0xbc, 0xbc, 0xbc])
        byte = bytes([0x16])
        byte_data = bytes([0xaa, 0xaa, 0xaa])

        xor = bo.one_byte_xor(byte_data, byte)

        self.assertEqual(result, xor)

    def test_repeating_key_xor_encrypt(self):
        result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20'
        key = UTF8Converter().decode('ICE')
        text = UTF8Converter().decode("Burning 'em, if you ain't quick and nimble")
        cipher = bo.repeating_key_xor(text, key)
        cipher_hex = HexConverter().encode(cipher)
        self.assertEqual(result, cipher_hex)

    def test_repeating_key_xor_decrypt(self):
        result = "Burning 'em, if you ain't quick and nimble"
        key = UTF8Converter().decode('ICE')
        cipher = HexConverter().decode(
                '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20')
        byte_text = bo.repeating_key_xor(cipher, key)
        text = UTF8Converter().encode(byte_text)
        self.assertEqual(result, text)


if __name__ == '__main__':
    unittest.main()
