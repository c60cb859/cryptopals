#!/bin/python3

import unittest

from crypto_tools.data_conversion import HexConverter
from crypto_tools.data_conversion import Base64Converter
from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import IntConverter


class DataConversion(unittest.TestCase):
    def test_hex_to_bytes(self):
        result = bytes([0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x18])
        hex_string = '1b37373331363f7818'

        byte = HexConverter().decode(hex_string)

        self.assertEqual(result, byte)

    def test_base64_to_bytes(self):
        result = b'Man is distinguished, not only by his reason, but by this'
        base64_string = 'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz'

        byte = Base64Converter().decode(base64_string)

        self.assertEqual(result, byte)

    def test_utf8_to_bytes(self):
        result = b'Man is distinguished, not only by his reason, but by this'
        utf8_string = 'Man is distinguished, not only by his reason, but by this'

        byte = UTF8Converter().decode(utf8_string)

        self.assertEqual(result, byte)

    def test_int_to_single_byte(self):
        result = bytes([0xc9])
        integer = 201

        byte = IntConverter().decode(integer)

        self.assertEqual(result, byte)

    def test_bytes_to_hex(self):
        result = '1b37373331363f7818'
        byte = bytes([0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x18])

        hex_string = HexConverter().encode(byte)

        self.assertEqual(result, hex_string)

    def test_bytes_to_base64(self):
        result = 'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz'
        byte = b'Man is distinguished, not only by his reason, but by this'

        base64_string = Base64Converter().encode(byte)

        self.assertEqual(result, base64_string)

    def test_bytes_to_utf8(self):
        result = 'Man is distinguished, not only by his reason, but by this'
        byte = b'Man is distinguished, not only by his reason, but by this'

        utf8_string = UTF8Converter().encode(byte)

        self.assertEqual(result, utf8_string)


if __name__ == '__main__':
    unittest.main()
