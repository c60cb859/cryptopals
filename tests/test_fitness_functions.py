#!/bin/python3

import unittest
import crypto_tools.firness_functions as fit

from crypto_tools.data_conversion import UTF8Converter


class FitnessFunctions(unittest.TestCase):
    def test_score_english_text(self):
        result = 60
        text = 'this is a test'

        score = fit.score_english_text(text)

        self.assertEqual(result, score)

    def test_hamming_distance(self):
        result = 37
        text1 = UTF8Converter().decode('this is a test')
        text2 = UTF8Converter().decode('wokka wokka!!!')

        edit_distance = fit.hamming_distance(text1, text2)

        self.assertEqual(result, edit_distance)


if __name__ == '__main__':
    unittest.main()
