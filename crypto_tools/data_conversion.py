#!/bin/python3

import base64
import codecs

from math import floor, ceil, log2


class DataConverter:
    def encode(self, data):
        '''Encode take a bytearray and convert it to another type, and returns it'''
        pass

    def decode(self, data):
        '''Decode takes data and convert it to a bytearray, and returns it'''
        pass


class HexConverter(DataConverter):
    def encode(self, data):
        hex_string = data.hex()
        return hex_string

    def decode(self, data):
        byte_data = bytearray.fromhex(data)
        return byte_data


class Base64Converter(DataConverter):
    def encode(self, data):
        base64_string = codecs.encode(data, 'base64')
        utf8_printable = base64_string.decode('utf-8')[:-1]
        return utf8_printable

    def decode(self, data):
        byte_data = base64.b64decode(data)
        return byte_data


class UTF8Converter(DataConverter):
    def encode(self, data):
        utf8_string = data.decode('latin-1')
        return utf8_string

    def decode(self, data):
        byte_data = data.encode('utf-8')
        return byte_data


class IntConverter(DataConverter):
    def encode(self, data):
        return int.from_bytes(data, byteorder='big')

    def decode(self, data):
        if data == 0:
            return bytearray([data])
        size = ceil(floor(log2(data) + 1)/8)
        return int.to_bytes(data, size, byteorder='big')
