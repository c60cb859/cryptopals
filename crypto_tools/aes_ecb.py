#!/bin/python3

from Crypto.Cipher import AES
from .byte_data import ByteData


class AesECB:
    def __init__(self, data):
        self._data = data

    def encrypt(self, key):
        algrorithm = AES.new(key.get_data(), AES.MODE_ECB)
        cipher = ByteData(algrorithm.encrypt(self._data.get_data()))

        return cipher

    def decrypt(self, key):
        algrorithm = AES.new(key.get_data(), AES.MODE_ECB)
        cleartext = ByteData(algrorithm.decrypt(self._data.get_data()))

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
