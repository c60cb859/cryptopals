#!/bin/python3

import crypto_tools.byte_operations as bo
import crypto_tools.data_conversion as dc
import crypto_tools.firness_functions as fit
import crypto_tools.cipher_operations as co


def break_one_byte_xor(byte_data):
    score = 1000000
    best_text = ''
    key = ''

    for num in range(255):
        byte = dc.int_to_single_byte(num)
        xor_byte_data = bo.one_byte_xor(byte_data, byte)
        text = dc.bytes_to_utf8(xor_byte_data)
        temp_score = fit.score_english_text(text)
        if temp_score > score:
            continue
        score = temp_score
        best_text = text
        key = dc.bytes_to_utf8(byte)

    return best_text, key


def break_repeating_xor(byte_data):
    key_size = fit.find_repeating_xor_key_size(byte_data)
    divided_cipher = co.divide_cipher(byte_data, key_size)
    transposed_cipher = co.transpose_cipher_list(divided_cipher)
    key = ''

    for line in transposed_cipher:
        key += break_one_byte_xor(line)[1]
    byte_key = dc.utf8_to_bytes(key)
    original_bytes = bo.repeating_key_xor(byte_data, byte_key)
    original_text = dc.bytes_to_utf8(original_bytes)

    return original_text, key
