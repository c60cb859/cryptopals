#!/usr/bin/env python3

import unittest
import pytest

from crypto_tools import ByteData
from crypto_tools import HexConverter
from crypto_tools import UTF8Converter


class TestByteData(unittest.TestCase):
    def test_xor_sigle_byte(self):
        result = ByteData(bytes([0xbc]))
        byte1 = ByteData(bytes([0x16]))
        byte2 = ByteData(bytes([0xaa]))

        xor = byte1 ^ byte2

        self.assertEqual(result, xor)

    def test_xor_multiple_bytes(self):
        result = ByteData(b'\x04'*16)
        byte1 = ByteData(b'\x04'*16)
        byte2 = ByteData(b'\x00'*16)

        xor = byte1 ^ byte2

        self.assertEqual(result, xor)

    def test_getitem(self):
        result = ByteData(b'\x42')
        byte = ByteData(b'\x00\x00\x00\x00\x42\x00\x00\x00')

        self.assertEqual(result, byte[4])

    def test_setitem(self):
        result = ByteData(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        byte = ByteData(b'\x00\x00\x00\x03\x04\x05\x06\x07')
        byte[1] = 1
        byte[2] = b'\x02'

        self.assertEqual(result, byte)

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

    def test_pkcs7_padding(self):
        result = ByteData(b'some text\x06\x06\x06\x06\x06\x06')
        data = ByteData(b'some text')
        block_size = 15

        padded_data = data.pkcs7_pad(block_size)

        self.assertEqual(result, padded_data)

    def test_pkcs7_padding_remove_correct(self):
        result = ByteData(b'some text')
        data = ByteData(b'some text\x06\x06\x06\x06\x06\x06')

        padded_data = data.pkcs7_pad_remove()

        self.assertEqual(result, padded_data)

    def test_pkcs7_padding_remove_wrong_length(self):
        result = "Data does not have valid pkcs7 padding: b't\x07\x07\x07\x07\x07\x07'"
        data = ByteData(b'some text\x07\x07\x07\x07\x07\x07')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)

    def test_pkcs7_padding_remove_wrong_padding(self):
        result = "Data does not have valid pkcs7 padding: b'\x01\x02\x03\x04\x05\x06'"
        data = ByteData(b'some text\x01\x02\x03\x04\x05\x06')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)


if __name__ == '__main__':
    unittest.main()
