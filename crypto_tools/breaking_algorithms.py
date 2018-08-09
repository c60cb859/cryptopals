#!/bin/python3

import crypto_tools.byte_operations as bo
import crypto_tools.firness_functions as fit
import crypto_tools.cipher_operations as co

from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import IntConverter


def break_one_byte_xor(byte_data):
    score = 1000000
    best_text = ''
    key = ''

    for num in range(255):
        byte = IntConverter().decode(num)
        xor_byte_data = bo.one_byte_xor(byte_data, byte)
        text = UTF8Converter().encode(xor_byte_data)
        temp_score = fit.score_english_text(text)
        if temp_score > score:
            continue
        score = temp_score
        best_text = text
        key = UTF8Converter().encode(byte)

    return best_text, key


def break_repeating_xor(byte_data):
    key_size = fit.find_repeating_xor_key_size(byte_data)
    divided_cipher = co.divide_cipher(byte_data, key_size)
    transposed_cipher = co.transpose_cipher_list(divided_cipher)
    key = ''

    for line in transposed_cipher:
        key += break_one_byte_xor(line)[1]
    byte_key = UTF8Converter().decode(key)
    original_bytes = bo.repeating_key_xor(byte_data, byte_key)
    original_text = UTF8Converter().encode(original_bytes)

    return original_text, key
