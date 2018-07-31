#!/bin/python3

from Crypto.Cipher import AES


def enc_aes_ecb(key, cleartext):
    algrorithm = AES.new(key, AES.MODE_ECB)
    cipher = algrorithm.encrypt(cleartext)

    return cipher


def dec_aes_ecb(key, cipher):
    algrorithm = AES.new(key, AES.MODE_ECB)
    cleartext = algrorithm.decrypt(cipher)

    return cleartext


def split_cipher(block_size, cipher):
    data = list()
    for num in range(0, len(cipher), block_size):
        data.append(cipher[num:num+block_size])

    return data


def fint_duplicates(data):
    seen = dict()
    duplicates = list()

    for block in data:
        if block not in seen:
            seen[block] = 1
        else:
            if seen[block] == 1:
                duplicates.append(block)
            seen[block] += 1

    return duplicates


def detect_ecb_mode(block_size, cipher):
    blocks = split_cipher(block_size, cipher)
    duplicates = fint_duplicates(blocks)

    if len(duplicates) > 0:
        return True
    return False
