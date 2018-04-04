#!/bin/python3


import numpy


def score_english_text(text):
    char_value = {'E': 0, 'e': 0,
                  'T': 1, 't': 1,
                  'A': 2, 'a': 2,
                  'O': 3, 'o': 3,
                  'I': 4, 'i': 4,
                  'N': 5, 'n': 5,
                  ' ': 6, ' ': 6,
                  'S': 7, 's': 7,
                  'H': 8, 'h': 8,
                  'R': 9, 'r': 9,
                  'D': 10, 'd': 10,
                  'L': 11, 'l': 11,
                  'U': 12, 'u': 12}
    score = 0
    for char in text:
        if char not in char_value:
            score += 100
            continue
        score += char_value[char]
    return score


def hamming_distance(byte_data1, byte_data2):
    edit_distance = 0

    for byte1, byte2 in zip(byte_data1, byte_data2):
        bin1 = "{0:08b}".format(byte1)
        bin2 = "{0:08b}".format(byte2)
        for bit1, bit2 in zip(bin1, bin2):
            if bit1 != bit2:
                edit_distance += 1

    return edit_distance


def find_repeating_xor_key_size(byte_data, min_key_size=2, max_key_size=40, number_of_blocks=4):
    key_list = list()

    for key_size in range(min_key_size, max_key_size):
        block_list = list()
        ed_list = list()
        key_dict = {}

        for block_num in range(number_of_blocks):
            start_byte = block_num * key_size
            end_byte = block_num * key_size + key_size
            block_list.append(byte_data[start_byte:end_byte])

        for block_num1 in range(len(block_list)):
            for block_num2 in range(block_num1 + 1, len(block_list)):
                edit_distance = hamming_distance(block_list[block_num1], block_list[block_num2]) / key_size
                ed_list.append(edit_distance)

        edit_distance = numpy.mean(ed_list)
        key_dict['Key size'] = key_size
        key_dict['Edit distance'] = edit_distance
        key_list.append(key_dict)

    keys = sorted(key_list, key=lambda k: k['Edit distance'])[:4]

    return keys[0]['Key size']
