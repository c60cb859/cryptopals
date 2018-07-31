#!/bin/python3

import unittest
import crypto_tools.data_conversion as dc
import crypto_tools.byte_operations as bo
import crypto_tools.breaking_algorithms as ba
import crypto_tools.firness_functions as fit
import crypto_tools.aes_ecb as aes


class CryptoChallengeSet1(unittest.TestCase):
    def test_convert_hex_to_base64(self):
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

    def test_detect_single_character_xor(self):
        result = "Now that the party is jumping\n"
        result_key = '5'

        with open('files/4.txt') as f:
            score = 10000
            best_string = ''
            for line in f:
                hex_string = line.rstrip('\n')
                byte_data = dc.hex_to_bytes(hex_string)
                string, temp_key = ba.break_one_byte_xor(byte_data)
                temp_score = fit.score_english_text(string)
                if temp_score > score:
                    continue
                score = temp_score
                best_string = string
                key = temp_key

        self.assertEqual(result, best_string)
        self.assertEqual(result_key, key)

    def test_implement_repeating_key_xor(self):
        result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527' +\
                 '2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        key = dc.utf8_to_bytes('ICE')
        text = dc.utf8_to_bytes("Burning 'em, if you ain't quick and nimble\n" +
                                'I go crazy when I hear a cymbal')
        cipher = bo.repeating_key_xor(text, key)
        cipher_hex = dc.bytes_to_hex(cipher)

        self.assertEqual(result, cipher_hex)

    def test_breaking_repeating_key_xor(self):
        result = 'Terminator X: Bring the noise'

        with open('files/6.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        byte_data = dc.base64_to_bytes(base64_cipher_text)
        text, key = ba.break_repeating_xor(byte_data)

        self.assertEqual(result, key)

    def test_aes_in_ecb_mode(self):
        with open('files/7_result.txt') as f:
            result = f.read()

        with open('files/7.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        key = 'YELLOW SUBMARINE'
        byte_data = dc.base64_to_bytes(base64_cipher_text)
        cleartext = dc.bytes_to_utf8(aes.dec_aes_ecb(key, byte_data))

        self.assertEqual(result, cleartext)


if __name__ == '__main__':
    unittest.main()
