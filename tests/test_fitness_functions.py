#!/bin/python3

import unittest
import crypto_tools.firness_functions as fit

from crypto_tools.data_conversion import UTF8Converter
from crypto_tools.firness_functions import EnglishScore


class FitnessFunctions(unittest.TestCase):
    def test_hamming_distance(self):
        result = 37
        text1 = UTF8Converter().decode('this is a test')
        text2 = UTF8Converter().decode('wokka wokka!!!')

        edit_distance = fit.hamming_distance(text1, text2)

        self.assertEqual(result, edit_distance)


class TestEnglishScore(unittest.TestCase):
    def test_score_english_text(self):
        result = 60
        text = 'this is a test'

        score = EnglishScore().score(text)

        self.assertEqual(result, score)


if __name__ == '__main__':
    unittest.main()
