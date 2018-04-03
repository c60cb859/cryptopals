#!/bin/python3


import unittest
import crypto_tools.data_conversion as dc
import crypto_tools.byte_operations as bo
import crypto_tools.breaking_algorithms as ba


class CryptoChallengeSet1(unittest.TestCase):
    def test_convert_hex_to_string(self):
        result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

        byte_data = dc.hex_to_bytes(hex_string)
        base64_string = dc.bytes_to_base64(byte_data)

        self.assertEqual(result, base64_string)

    def test_fixed_xor(self):
        result = '746865206b696420646f6e277420706c6179'
        hex_string1 = '1c0111001f010100061a024b53535009181c'
        hex_string2 = '686974207468652062756c6c277320657965'

        byte_data1 = dc.hex_to_bytes(hex_string1)
        byte_data2 = dc.hex_to_bytes(hex_string2)

        byte_xor = bo.fixed_xor(byte_data1, byte_data2)
        hex_xor = dc.bytes_to_hex(byte_xor)

        self.assertEqual(result, hex_xor)

    def test_single_byte_xor_chiper(self):
        result = "Cooking MC's like a pound of bacon"
        result_key = 'X'
        hex_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        byte_data = dc.hex_to_bytes(hex_string)

        best_string, key = ba.break_one_byte_xor(byte_data)

        self.assertEqual(result, best_string)
        self.assertEqual(result_key, key)


if __name__ == '__main__':
    unittest.main()
