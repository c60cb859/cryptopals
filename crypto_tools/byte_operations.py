#!/bin/python3


from itertools import cycle


def fixed_xor(byte_data1, byte_data2):
    if len(byte_data1) != len(byte_data2):
        raise ValueError('Inputs not same size')
    xor_byte_data = bytearray()

    for byte1, byte2 in zip(byte_data1, byte_data2):
        xor_byte_data.append(byte1 ^ byte2)

    return xor_byte_data


def one_byte_xor(byte_data, byte):
    if len(byte) > 1:
        raise ValueError('byte input is more than one byte')
    xor_byte_data = bytearray()

    for byte_d in byte_data:
        xor_byte_data.append(byte_d ^ byte[0])

    return xor_byte_data


def repeating_key_xor(byte_data, key):
    key_ring = cycle(key)
    xor_byte_data = bytearray()

    for byte in byte_data:
        xor_byte_data.append(byte ^ next(key_ring))

    return xor_byte_data
