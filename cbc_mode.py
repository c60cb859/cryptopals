#!/bin/python3

import crypto_tools.aes_ecb as aes
import crypto_tools.data_conversion as dc
import crypto_tools.byte_operations as bo


block_size = 16
IV = dc.utf8_to_bytes('0' * block_size)
key = 'YELLOW SUBMARINE'

cleartext = 'CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,' +\
            ' despite the fact that a block cipher natively only transforms individual blocks'

print(len(cleartext) % 16)
padded_cleartext = aes.padding_pkcs7(block_size, cleartext)
print(len(padded_cleartext)/block_size)
data = aes.split_cipher(block_size, padded_cleartext)

byte_data = list()
for block in data:
    byte_data.append(dc.utf8_to_bytes(block))

byte_cipher = list()
print(len(byte_data[-1]))

for num in range(0, len(byte_data)):
    if num == 0:
        xored_block = bo.fixed_xor(IV, byte_data[num])
    else:
        xored_block = bo.fixed_xor(byte_cipher[num-1], byte_data[num])
    byte_cipher.append(aes.enc_aes_ecb(key, bytes(xored_block)))

print(byte_cipher)
