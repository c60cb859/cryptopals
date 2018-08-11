#!/bin/python3

import unittest

from crypto_tools.data_conversion import HexConverter
from crypto_tools.data_conversion import Base64Converter
from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.byte_operations import ByteData

import crypto_tools.breaking_algorithms as ba
import crypto_tools.firness_functions as fit
import crypto_tools.aes_ecb as aes


class CryptoChallengeSet1(unittest.TestCase):
    def test_convert_hex_to_base64(self):
        result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

        byte_data = HexConverter().decode(hex_string)
        base64_string = Base64Converter().encode(byte_data)

        self.assertEqual(result, base64_string)

    def test_fixed_xor(self):
        result = '746865206b696420646f6e277420706c6179'
        hex_string1 = '1c0111001f010100061a024b53535009181c'
        hex_string2 = '686974207468652062756c6c277320657965'

        data1 = ByteData(hex_string1, HexConverter())
        data2 = ByteData(hex_string2, HexConverter())

        data_xor = data1 ^ data2
        hex_xor = data_xor.encode(HexConverter())

        self.assertEqual(result, hex_xor)

    def test_single_byte_xor_chiper(self):
        result = ByteData("Cooking MC's like a pound of bacon", UTF8Converter())
        result_key = ByteData('X', UTF8Converter())
        data = ByteData('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', HexConverter())

        best_string, key = ba.break_one_byte_xor(data)

        self.assertEqual(result, best_string)
        self.assertEqual(result_key, key)

    def test_detect_single_character_xor(self):
        result = ByteData("Now that the party is jumping\n", UTF8Converter())
        result_key = ByteData('5', UTF8Converter())

        with open('files/4.txt') as f:
            score = 10000
            best_string = ByteData()
            for line in f:
                data = ByteData(line.rstrip('\n'), HexConverter())
                string, temp_key = ba.break_one_byte_xor(data)
                temp_score = fit.score_english_text(string.encode(UTF8Converter()))
                if temp_score > score:
                    continue
                score = temp_score
                best_string = string
                key = temp_key

        self.assertEqual(result, best_string)
        self.assertEqual(result_key, key)

    def test_implement_repeating_key_xor(self):
        result = ByteData('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527' +
                          '2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f',
                          HexConverter())
        key = ByteData('ICE', UTF8Converter())
        text = ByteData("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
                        UTF8Converter())
        cipher = text.repeating_key_xor(key)

        self.assertEqual(result, cipher)

    def test_breaking_repeating_key_xor(self):
        result = ByteData('Terminator X: Bring the noise', UTF8Converter())

        with open('files/6.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        data = ByteData(base64_cipher_text, Base64Converter())
        text, key = ba.break_repeating_xor(data)

        self.assertEqual(result, key)

    def test_aes_in_ecb_mode(self):
        with open('files/7_result.txt') as f:
            result = f.read()

        with open('files/7.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        key = ByteData('YELLOW SUBMARINE', UTF8Converter())
        data = ByteData(base64_cipher_text, Base64Converter())
        cleartext = aes.dec_aes_ecb(key, data)

        self.assertEqual(result, cleartext.encode(UTF8Converter()))

    def test_detect_aes_in_ecb_mode(self):
        result = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf' +\
                 '9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a' +\
                 '08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f' +\
                 'd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
        block_size = 16

        with open('files/8.txt') as f:
            data = f.read().split('\n')[:-1]

        for cipher in data:
            byte_cipher = UTF8Converter().decode(cipher)
            if aes.detect_ecb_mode(block_size, byte_cipher):
                ecb_cipher = cipher
                break

        self.assertEqual(result, ecb_cipher)


if __name__ == '__main__':
    unittest.main()
