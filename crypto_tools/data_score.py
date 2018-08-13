#!/bin/python3


class DataScore:
    _score_table = dict()
    _undefined_score = 100

    def score(self, cleartext):
        score = 0
        for char in cleartext:
            if char not in self._score_table:
                score += self._undefined_score
                continue
            score += self._score_table[char]
        return score


class EnglishScore(DataScore):
    _score_table = {'E': 0, 'e': 0,
                    'T': 1, 't': 1,
                    'A': 2, 'a': 2,
                    'O': 3, 'o': 3,
                    'I': 4, 'i': 4,
                    'N': 5, 'n': 5,
                    ' ': 6, ' ': 6,
                    'S': 7, 's': 7,
                    'H': 8, 'h': 8,
                    'R': 9, 'r': 9,
                    'D': 10, 'd': 10,
                    'L': 11, 'l': 11,
                    'U': 12, 'u': 12}
