#!/usr/bin/env python3

from math import ceil
from .data_conversion import IntConverter


class ByteData:
    def __init__(self, data=b'', converter=None):
        if converter is None:
            self._bytes = bytearray(data)
        else:
            self._bytes = converter.decode(data)

    def __eq__(self, other):
        return self._bytes == other

    def __add__(self, other):
        return ByteData(self._bytes + other._bytes)

    def __mul__(self, interger):
        return ByteData(self._bytes * interger)

    def __len__(self):
        if isinstance(self._bytes, int):
            return 1
        return len(self._bytes)

    def __iter__(self):
        return iter(self._bytes)

    def __getitem__(self, index):
        data = self._bytes[index]
        if isinstance(data, int):
            return ByteData(self._bytes[index], IntConverter())
        return ByteData(self._bytes[index])

    def __setitem__(self, index, value):
        if isinstance(value, int):
            self._bytes[index] = value
        else:
            self._bytes[index] = int.from_bytes(value, 'big')

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
        key_size = len(key)
        data_size = len(self)
        multiplier = ceil(data_size/key_size)

        xor_data = self ^ (key * multiplier)[:data_size]

        return xor_data

    def pkcs7_pad(self, block_size):
        padding_lenght = (block_size - len(self) % block_size) % block_size
        if padding_lenght == 0:
            padding = ByteData(bytes([block_size] * block_size))
        else:
            padding = ByteData(bytes([padding_lenght]) * padding_lenght)
        return self + padding

    def pkcs7_pad_remove(self):
        if isinstance(self.get_data()[-1], int):
            padding_lenght = self.get_data()[-1]
            padding = self[-1*padding_lenght:]
            if padding == ByteData(bytes([padding_lenght])*padding_lenght):
                return self[:-1*padding_lenght]
            raise Exception('Data does not have valid pkcs7 padding: {}'.format(padding.get_data()))
        return self

    def hamming_distance(self, data):
        edit_distance = 0

        for byte1, byte2 in zip(self._bytes, data):
            bin1 = "{0:08b}".format(byte1)
            bin2 = "{0:08b}".format(byte2)
            for bit1, bit2 in zip(bin1, bin2):
                if bit1 != bit2:
                    edit_distance += 1

        return edit_distance
