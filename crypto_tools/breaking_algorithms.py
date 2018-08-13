#!/bin/python3
import numpy

import crypto_tools.cipher_operations as co

from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.data_conversion import IntConverter
from crypto_tools.byte_data import ByteData
from crypto_tools.data_score import EnglishScore


def find_repeating_xor_key_size(data, min_key_size=2, max_key_size=40, number_of_blocks=4):
    key_list = list()

    for key_size in range(min_key_size, max_key_size):
        block_list = list()
        ed_list = list()
        key_dict = {}

        for block_num in range(number_of_blocks):
            start_byte = block_num * key_size
            end_byte = block_num * key_size + key_size
            block_list.append(data[start_byte:end_byte])

        for block_num1 in range(len(block_list)):
            for block_num2 in range(block_num1 + 1, len(block_list)):
                edit_distance = block_list[block_num1].hamming_distance(block_list[block_num2]) / key_size
                ed_list.append(edit_distance)

        edit_distance = numpy.mean(ed_list)
        key_dict['Key size'] = key_size
        key_dict['Edit distance'] = edit_distance
        key_list.append(key_dict)

    keys = sorted(key_list, key=lambda k: k['Edit distance'])[:4]

    return keys[0]['Key size']


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
    key_size = find_repeating_xor_key_size(data)
    divided_cipher = co.divide_cipher(data.get_data(), key_size)
    transposed_cipher = co.transpose_cipher_list(divided_cipher)
    key = ByteData()

    for line in transposed_cipher:
        byte_line = ByteData(line)
        key += break_one_byte_xor(byte_line)[1]
    original = data.repeating_key_xor(key)

    return original, key
