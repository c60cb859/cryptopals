#!/bin/python3

import crypto_tools.aes_ecb as aes
import crypto_tools.data_conversion as dc
import crypto_tools.byte_operations as bo


def enc_aes_cbc(cleartext, key, iv=0, block_size=16):
    if iv == 0:
        iv = bytes(block_size)
    prev_block = iv

    padded_cleartext = aes.padding_pkcs7(block_size, cleartext)
    data = aes.split_cipher(block_size, padded_cleartext)

    byte_cipher = list()

    for block in data:
        xored_block = bo.fixed_xor(prev_block, block)
        byte_cipher.append(aes.enc_aes_ecb(key, bytes(xored_block)))
        prev_block = byte_cipher[-1]

    cipher = bytes()

    for block in byte_cipher:
        cipher += block

    return cipher


def dec_aes_cbc(ciphertext, key, iv=0, block_size=16):
    if iv == 0:
        iv = bytes(block_size)
    prev_block = iv

    data = aes.split_cipher(block_size, ciphertext)

    byte_cleartext = list()

    for block in data:
        xored_block = aes.dec_aes_ecb(key, block)
        byte_cleartext.append(bo.fixed_xor(prev_block, xored_block))
        prev_block = block

    cleartext = bytes()

    for block in byte_cleartext:
        cleartext += block

    return cleartext


key = 'YELLOW SUBMARINE'

cleartext = 'CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,' +\
            'despite the fact that a block cipher natively only transforms individual blocks.'
byte_cleartext = dc.utf8_to_bytes(cleartext)

dec_cleartext = dec_aes_cbc(enc_aes_cbc(byte_cleartext, key), key)


print('-'*10 + 'TESTING' + '-'*10)
print(dec_cleartext)
print('-'*10 + 'TESTING' + '-'*10)

with open('files/10.txt') as f:
    base64_cipher_text = f.read().replace('\n', '')

cipher = dc.base64_to_bytes(base64_cipher_text)
dec_cleartext = dec_aes_cbc(cipher, key)

print(dc.bytes_to_utf8(dec_cleartext))
