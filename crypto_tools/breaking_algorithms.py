#!/bin/python3

import crypto_tools.firness_functions as fit
import crypto_tools.cipher_operations as co

from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import IntConverter
from crypto_tools.byte_operations import ByteData
from crypto_tools.firness_functions import EnglishScore


def break_one_byte_xor(data):
    score = 1000000
    best_text = ByteData()
    key = ByteData()

    for num in range(255):
        byte = ByteData(num, IntConverter())
        xor_data = data.repeating_key_xor(byte)
        text = xor_data.encode(UTF8Converter())
        temp_score = EnglishScore().score(text)
        if temp_score > score:
            continue
        score = temp_score
        best_text = xor_data
        key = byte

    return best_text, key


def break_repeating_xor(data):
    key_size = fit.find_repeating_xor_key_size(data.get_data())
    divided_cipher = co.divide_cipher(data.get_data(), key_size)
    transposed_cipher = co.transpose_cipher_list(divided_cipher)
    key = ByteData()

    for line in transposed_cipher:
        byte_line = ByteData(line)
        key += break_one_byte_xor(byte_line)[1]
    original = data.repeating_key_xor(key)

    return original, key
