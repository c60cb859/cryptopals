#!/bin/python3

from itertools import cycle


class ByteData:
    def __init__(self, data=b'', converter=None):
        if converter is None:
            self._bytes = data
        else:
            self._bytes = converter.decode(data)

    def __eq__(self, other):
        return self._bytes == other

    def __add__(self, other):
        return ByteData(self._bytes + other._bytes)

    def __len__(self):
        return len(self._bytes)

    def __iter__(self):
        return iter(self._bytes)

    def __getitem__(self, index):
        return ByteData(self._bytes[index])

    def __xor__(self, other):
        if len(self) != len(other):
            raise ValueError('Inputs not same size')

        byte_data = bytearray()

        for byte1, byte2 in zip(self, other):
            byte_data.append(byte1 ^ byte2)

        data = ByteData(byte_data)
        return data

    def get_data(self):
        return bytes(self._bytes)

    def encode(self, converter):
        return converter.encode(self._bytes)

    def pkcs7_pad(self, block_size):
        padding_lenght = (block_size - len(self) % block_size) % block_size
        padding = ByteData(bytes([padding_lenght]) * padding_lenght)

        return self + padding


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
