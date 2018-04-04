#!/bin/python3


import unittest
import crypto_tools.data_conversion as dc
import crypto_tools.byte_operations as bo


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
        key = dc.utf8_to_bytes('ICE')
        text = dc.utf8_to_bytes("Burning 'em, if you ain't quick and nimble")
        cipher = bo.repeating_key_xor(text, key)
        cipher_hex = dc.bytes_to_hex(cipher)
        self.assertEqual(result, cipher_hex)

    def test_repeating_key_xor_decrypt(self):
        result = "Burning 'em, if you ain't quick and nimble"
        key = dc.utf8_to_bytes('ICE')
        cipher = dc.hex_to_bytes('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20')
        byte_text = bo.repeating_key_xor(cipher, key)
        text = dc.bytes_to_utf8(byte_text)
        self.assertEqual(result, text)


if __name__ == '__main__':
    unittest.main()
