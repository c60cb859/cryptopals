#!/bin/python3


def score_english_text(text):
    char_value = {'E': 0, 'e': 0,
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
    score = 0
    for char in text:
        if char not in char_value:
            score += 100
            continue
        score += char_value[char]
    return score
