#!/usr/bin/env python3

import unittest

from crypto_tools import EnglishScore


class TestEnglishScore(unittest.TestCase):
    def test_score_english_text(self):
        result = 60
        text = 'this is a test'

        score = EnglishScore().score(text)

        self.assertEqual(result, score)


if __name__ == '__main__':
    unittest.main()
