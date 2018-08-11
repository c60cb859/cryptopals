#!/bin/python3

import crypto_tools.aes_ecb as aes

from crypto_tools.byte_operations import ByteData
from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import Base64Converter


def enc_aes_cbc(cleartext, key, iv=0, block_size=16):
    if iv == 0:
        iv = ByteData(bytes(block_size))
    prev_block = iv

    padded_cleartext = cleartext.pkcs7_pad(block_size)
    cipher = ByteData()

    for index in range(0, len(padded_cleartext), block_size):
        block = padded_cleartext[index:index+block_size]
        xored_block = block ^ prev_block
        cipher_block = aes.enc_aes_ecb(key, xored_block)
        cipher += cipher_block
        prev_block = cipher_block

    return cipher


def dec_aes_cbc(ciphertext, key, iv=0, block_size=16):
    if iv == 0:
        iv = ByteData(bytes(block_size))
    prev_block = iv

    cleartext = ByteData()

    for index in range(0, len(ciphertext), block_size):
        block = ciphertext[index:index+block_size]
        xored_block = aes.dec_aes_ecb(key, block)
        cleartext += xored_block ^ prev_block
        prev_block = block

    return cleartext


key = ByteData('YELLOW SUBMARINE', UTF8Converter())

cleartext = 'CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, ' +\
            'despite the fact that a block cipher natively only transforms individual blocks.'
byte_cleartext = ByteData(cleartext, UTF8Converter())

enc_cleartext = enc_aes_cbc(byte_cleartext, key)
dec_cleartext = dec_aes_cbc(enc_cleartext, key)


print('-'*10 + 'TESTING' + '-'*10)
print(dec_cleartext.encode(UTF8Converter()))
print(dec_cleartext._bytes)
print('-'*10 + 'TESTING' + '-'*10)
print(len(cleartext))
print(len(dec_cleartext))


with open('files/10.txt') as f:
    base64_cipher_text = f.read().replace('\n', '')

cipher = ByteData(base64_cipher_text, Base64Converter())

dec_cleartext = dec_aes_cbc(cipher, key)
enc_cleartext = enc_aes_cbc(dec_cleartext, key)

print(cipher.encode(Base64Converter()) == enc_cleartext.encode(Base64Converter()))
