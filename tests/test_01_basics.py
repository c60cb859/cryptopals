import unittest
from crypto_tools.data_conversion import hex_to_bytes, bytes_to_base64, bytes_to_hex
from crypto_tools.byte_operations import fixed_xor


class CryptoChallengeSet1(unittest.TestCase):
    def test_convert_hex_to_string(self):
        result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

        byte_data = hex_to_bytes(hex_string)
        base64_string = bytes_to_base64(byte_data)

        self.assertEqual(base64_string, result)

    def test_fixed_xor(self):
        result = '746865206b696420646f6e277420706c6179'
        hex_string1 = '1c0111001f010100061a024b53535009181c'
        hex_string2 = '686974207468652062756c6c277320657965'

        byte_data1 = hex_to_bytes(hex_string1)
        byte_data2 = hex_to_bytes(hex_string2)

        byte_xor = fixed_xor(byte_data1, byte_data2)
        hex_xor = bytes_to_hex(byte_xor)

        self.assertEqual(hex_xor, result)


if __name__ == '__main__':
    unittest.main()
