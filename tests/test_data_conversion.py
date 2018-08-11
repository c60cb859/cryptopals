#!/bin/python3
'''This files contains unittests for the DataConverter classes'''

import unittest

from crypto_tools.data_conversion import HexConverter
from crypto_tools.data_conversion import Base64Converter
from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import IntConverter


class TestHexConverter(unittest.TestCase):
    '''Test classe for HexConverter'''
    def test_hex_decode(self):
        '''Make sure decoding hex works'''
        result = bytes([0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x18])
        hex_string = '1b37373331363f7818'

        byte = HexConverter().decode(hex_string)

        self.assertEqual(result, byte)

    def test_hex_encode(self):
        '''Make sure hex encoding works'''
        result = '1b37373331363f7818'
        byte = bytes([0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x18])

        hex_string = HexConverter().encode(byte)

        self.assertEqual(result, hex_string)


class TestBase64Converter(unittest.TestCase):
    '''Test classe for Base64Converter'''
    def test_base64_decode(self):
        '''Make sure decoding base64 works'''
        result = b'Man is distinguished, not only by his reason, but by this'
        base64_string = 'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz'

        byte = Base64Converter().decode(base64_string)

        self.assertEqual(result, byte)

    def test_base64_encode(self):
        '''Make sure base64 encoding works'''
        result = 'TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz'
        byte = b'Man is distinguished, not only by his reason, but by this'

        base64_string = Base64Converter().encode(byte)

        self.assertEqual(result, base64_string)


class TestUTF8Converter(unittest.TestCase):
    '''Test classe for UTF8Converter'''
    def test_utf8_decode(self):
        '''Make sure decoding UTF8 works'''
        result = b'Man is distinguished, not only by his reason, but by this'
        utf8_string = 'Man is distinguished, not only by his reason, but by this'

        byte = UTF8Converter().decode(utf8_string)

        self.assertEqual(result, byte)

    def test_utf8_encode(self):
        '''Make sure UTF8 encoding works'''
        result = 'Man is distinguished, not only by his reason, but by this'
        byte = b'Man is distinguished, not only by his reason, but by this'

        utf8_string = UTF8Converter().encode(byte)

        self.assertEqual(result, utf8_string)


class TestIntConverter(unittest.TestCase):
    '''Test classe for IntConverter'''
    def test_int_decode(self):
        '''Make sure decoding intergers works'''
        result = bytes([0x02, 0xc1, 0xd1])
        integer = 180689

        byte = IntConverter().decode(integer)

        self.assertEqual(result, byte)

    def test_int_encode(self):
        '''Make sure integer encoding works'''
        result = 180689
        byte = bytes([0x02, 0xc1, 0xd1])

        integer = IntConverter().encode(byte)

        self.assertEqual(result, integer)


if __name__ == '__main__':
    unittest.main()
