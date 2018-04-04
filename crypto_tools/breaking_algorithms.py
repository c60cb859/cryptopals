#!/bin/python3


import crypto_tools.byte_operations as bo
import crypto_tools.data_conversion as dc
import crypto_tools.firness_functions as fit


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
