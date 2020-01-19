#!/usr/bin/env python3

import unittest
import pytest
from crypto_tools import ByteData
from crypto_tools import UTF8Converter
from crypto_tools import Base64Converter
from crypto_tools import HexConverter
from crypto_tools import AesECB
from crypto_tools import AesCBC
from crypto_tools import AesOracle
from crypto_tools import ByteAtATimeECBSimple
from crypto_tools import ByteAtATimeECBHarder
from crypto_tools import EncryptedCookieGenerator
from crypto_tools import CBCBitFlippingAttack
from crypto_tools import BreakECBEncryption


class CryptoChallengeSet2(unittest.TestCase):
    def test_pkcs7_padding(self):
        result = ByteData(b'YELLOW SUBMARINE\x04\x04\x04\x04')

        block_size = 20
        data = ByteData(b'YELLOW SUBMARINE')

        padded_data = data.pkcs7_pad(block_size)

        self.assertEqual(result, padded_data)

    def test_implement_cbc_mode(self):
        with open('files/7_result.txt') as f:
            result = f.read()

        with open('files/10.txt') as f:
            base64_cipher_text = f.read().replace('\n', '')

        key = ByteData('YELLOW SUBMARINE', UTF8Converter())
        data = ByteData(base64_cipher_text, Base64Converter())
        cipher = AesCBC(data)

        cleartext = cipher.decrypt(key)

        self.assertEqual(result, cleartext.encode(UTF8Converter()))

    def test_ecb_cbc_detection_oracle(self):
        with open('files/7_result.txt') as f:
            data = ByteData(f.read(), UTF8Converter())
        key_size = 16
        test_count = 100

        for num in range(test_count):
            oracle = AesOracle(data)
            cipher = AesECB(oracle.encrypt())
            if cipher.verify_ecb_mode(key_size):
                encryption = 'ECB'
            else:
                encryption = 'CBC'

            self.assertEqual(oracle.encryption, encryption)

    def test_byte_at_a_time_ecb_decryption_simple(self):
        result = ByteData('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaG' +
                          'UgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJ' +
                          'IGp1c3QgZHJvdmUgYnkK', Base64Converter())

        backend = ByteAtATimeECBSimple()
        break_ecb = BreakECBEncryption(backend)
        if break_ecb.verify_ecb_mode():
            cleartext = break_ecb.break_ecb()
        data = ByteData(cleartext, UTF8Converter())

        self.assertEqual(result, data.pkcs7_pad_remove())

    def test_ecb_cut_and_paste(self):
        """
        What is encrypted:
            email=<user input>&uid=10&role=user
        Goal:
            have "role=admin"
            "&" and "=" is stripped form the input
        Method:
          Step 1:
            Create input so that "admin + padding" is in one block

            Block size 16 bytes
            |-------16-------|-------16-------|-------16-------|
            |email=<user inpu|t>&uid=10&role=u|ser.............|
            |email=AAAAAAAAAA|admin...........|&uid=10&role=use|r

            user input should be 10 A's plus 'admin' plus pkcs7 padding

          Step 2:
            Create input so that "role=" is the end of a block and
            "user + padding" is the only thing in the next block.

            Block size 16 bytes
            |-------16-------|-------16-------|-------16-------|
            |email=<user inpu|t>&uid=10&role=u|ser
            |email=AAAAAAAAAA|AAA&uid=10&role=|user

            user input should be 13 A's

          Step 3:
            Replace the last block in the chiper from step 2
            with the second block from the cipher in step 1
            and return the modified cipher to the backend

        """
        result = 'admin'
        backend = EncryptedCookieGenerator()
        # Step 1
        admin_input = 'A' * 10 + 'admin' + '\x0b' * 11
        admin_cipher_block = backend.encrypt(admin_input)[16:16*2]

        # Step 2
        user_input = 'A' * 13
        user_cipher = backend.encrypt(user_input)[:-16]

        # Step 3
        cipher = user_cipher + admin_cipher_block
        data = backend.decrypt(cipher)

        self.assertEqual(result, data['role'])

    def test_byte_at_a_time_ecb_decryption_harder(self):
        result = ByteData('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaG' +
                          'UgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJ' +
                          'IGp1c3QgZHJvdmUgYnkK', Base64Converter())

        backend = ByteAtATimeECBHarder()
        break_ecb = BreakECBEncryption(backend)
        if break_ecb.verify_ecb_mode():
            cleartext = break_ecb.break_ecb()
        data = ByteData(cleartext, UTF8Converter())

        self.assertEqual(result, data.pkcs7_pad_remove())

    def test_pkcs7_padding_remove_correct(self):
        result = ByteData(b'ICE ICE BABY')
        data = ByteData(b'ICE ICE BABY\x04\x04\x04\x04')

        padded_data = data.pkcs7_pad_remove()

        self.assertEqual(result, padded_data)

    def test_pkcs7_padding_remove_wrong_length(self):
        result = "Data does not have valid pkcs7 padding: b'Y\x07\x07\x07\x07'"
        data = ByteData(b'ICE ICE BABY\x05\x05\x05\x05')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)

    def test_pkcs7_padding_remove_wrong_padding(self):
        result = "Data does not have valid pkcs7 padding: b'\x01\x02\x03\x04'"
        data = ByteData(b'ICE ICE BABY\x01\x02\x03\x04')

        with pytest.raises(Exception) as info:
            assert(data.pkcs7_pad_remove())
            self.assertEqual(result, info)

    def test_cbc_bitflipping(self):
        """
        What is encrypted:
            comment1=cooking%20MCs;userdata=<user input>;comment2=%20like%20a%20pound%20of%20bacon
        Goal:
            have ";admin=true"
            ";" and "=" is stripped form the input
        Method:
          Step 1:
            Create evil input. To bypass the stripping of bad character
            bit flip the evil input for those character.
            Desired output:    A  A  A  A  A  ;  a  d  m  i  n  =  t  r  u  e
            Bitflipping mask: 00 00 00 00 00 01 00 00 00 00 00 01 00 00 00 00

          Step 2:
            Encrypt the bitflipped input, and split the cipher in blocks
            bitflip the block before the input block with the same mask

          Step 3:
            Decrypt the bitflipped cipher

          The diagram bitflip.png illustrates this attack
        """
        result = 'true'
        backend = CBCBitFlippingAttack()
        # Step 1
        evil_input = 'AAAAA;admin=true'
        evil_data = ByteData(evil_input, UTF8Converter())

        bitflip_mask = '00000000000100000000000100000000'
        bitflip_data = ByteData(bitflip_mask, HexConverter())

        xor_data = evil_data ^ bitflip_data
        # Step 2
        cipher = backend.encrypt(xor_data.encode(UTF8Converter()))
        prefix_cipher = cipher[:16]
        postfix_cipher = cipher[32:]
        evil_block = cipher[16:32] ^ bitflip_data

        evil_cihper = prefix_cipher + evil_block + postfix_cipher

        # Step 3
        data = backend.decrypt(evil_cihper)

        self.assertEqual(result, data['admin'])


if __name__ == '__main__':
    unittest.main()
