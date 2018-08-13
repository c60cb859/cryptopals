#!/bin/python3
import crypto_tools.cipher_operations as co

from .data_conversion import UTF8Converter
from .data_conversion import IntConverter
from .byte_data import ByteData


class RepeatingXor:
    def __init__(self, data, data_score):
        self._data = data
        self.data_score = data_score

        self.min_key_size = 2
        self.max_key_size = 40
        self.number_of_blocks = 4

        self.score = 1000000

    def _test_key_size(self, key_size):
        normalize_edit_distance = 0
        divider = (1 / 2) / (self.number_of_blocks - 1) * self.number_of_blocks

        for block_num1 in range(self.number_of_blocks):
            for block_num2 in range(block_num1 + 1, self.number_of_blocks):
                edit_distance = self._data[key_size*block_num1:key_size*block_num1+key_size].hamming_distance(
                                self._data[key_size*block_num2:key_size*block_num2+key_size])

                normalize_edit_distance += edit_distance / key_size

        return normalize_edit_distance / divider

    def break_one_byte_key(self):
        key = ByteData()

        for num in range(255):
            byte = ByteData(num, IntConverter())
            xor_data = self._data.repeating_key_xor(byte)
            text = xor_data.encode(UTF8Converter())
            temp_score = self.data_score.score(text)
            if temp_score > self.score:
                continue
            self.score = temp_score
            key = byte

        return key

    def find_key_size(self):
        best_key_size = 0
        best_edit_distance = 1000

        for key_size in range(self.min_key_size, self.max_key_size):
            edit_distance = self._test_key_size(key_size)
            if edit_distance < best_edit_distance:
                best_edit_distance = edit_distance
                best_key_size = key_size

        return best_key_size

    def break_multiple_byte_key(self):
        key_size = self.find_key_size()

        divided_cipher = co.divide_cipher(self._data.get_data(), key_size)

        transposed_cipher = co.transpose_cipher_list(divided_cipher)

        key = ByteData()

        for line in transposed_cipher:
            byte_line = RepeatingXor(ByteData(line), self.data_score)
            key += byte_line.break_one_byte_key()

        return key
