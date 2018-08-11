#!/bin/python3

from itertools import cycle
from crypto_tools.data_conversion import IntConverter


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

    def repeating_key_xor(self, key):
        key_ring = cycle(key)
        xor_data = ByteData()

        for byte in self:
            xor_data += ByteData(byte ^ next(key_ring), IntConverter())

        return xor_data

    def pkcs7_pad(self, block_size):
        padding_lenght = (block_size - len(self) % block_size) % block_size
        padding = ByteData(bytes([padding_lenght]) * padding_lenght)

        return self + padding
