#!/bin/python3


import unittest
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


if __name__ == '__main__':
    unittest.main()
