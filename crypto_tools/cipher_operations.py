#!/bin/python3


import crypto_tools.data_conversion as dc


def divide_cipher(byte_data, key_size):
    byte_block_list = list()

    for byte_block in range(int(len(byte_data) / key_size)):
        byte_block_list.append(byte_data[byte_block * key_size:byte_block * key_size + key_size])

    return byte_block_list


def transpose_cipher_list(cipher_list):
    transposed_byte_list = list()

    for byte_num in range(len(cipher_list[0])):
        temp_transposed_block = b''
        for block in cipher_list:
            temp_transposed_block += dc.int_to_single_byte(block[byte_num])
        transposed_byte_list.append(temp_transposed_block)

    return transposed_byte_list
