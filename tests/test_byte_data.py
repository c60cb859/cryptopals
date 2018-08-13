#!/bin/python3

import unittest

from crypto_tools.byte_data import ByteData
from crypto_tools.data_conversion import HexConverter
from crypto_tools.data_conversion import UTF8Converter


class ByteOperations(unittest.TestCase):
    def test_xor(self):
        result = ByteData(bytes([0xbc]))
        byte1 = ByteData(bytes([0x16]))
        byte2 = ByteData(bytes([0xaa]))

        xor = byte1 ^ byte2

        self.assertEqual(result, xor)

    def test_one_byte_xor(self):
        result = ByteData(bytes([0xbc, 0xbc, 0xbc]))
        byte = ByteData(bytes([0x16]))
        byte_data = ByteData(bytes([0xaa, 0xaa, 0xaa]))

        xor = byte_data.repeating_key_xor(byte)

        self.assertEqual(result, xor)

    def test_repeating_key_xor_encrypt(self):
        result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20'
        key = ByteData('ICE', UTF8Converter())
        text = ByteData("Burning 'em, if you ain't quick and nimble", UTF8Converter())
        cipher = text.repeating_key_xor(key)
        cipher_hex = cipher.encode(HexConverter())
        self.assertEqual(result, cipher_hex)

    def test_repeating_key_xor_decrypt(self):
        result = "Burning 'em, if you ain't quick and nimble"
        key = ByteData('ICE', UTF8Converter())
        cipher = ByteData('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20',
                          HexConverter())
        byte_text = cipher.repeating_key_xor(key)
        text = byte_text.encode(UTF8Converter())
        self.assertEqual(result, text)

    def test_hamming_distance(self):
        result = 37
        text1 = ByteData('this is a test', UTF8Converter())
        text2 = ByteData('wokka wokka!!!', UTF8Converter())

        edit_distance = text1.hamming_distance(text2)

        self.assertEqual(result, edit_distance)


if __name__ == '__main__':
    unittest.main()
