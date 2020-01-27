#!/usr/bin/env python3
from crypto_tools import ByteData
from crypto_tools import UTF8Converter
from crypto_tools import Base64Converter

from crypto_tools import CTRFixedNonce
from crypto_tools import RepeatingXor
from crypto_tools import EnglishScore


if __name__ == '__main__':
    backend = CTRFixedNonce()
    ciphers = backend.encrypt()
    lengths = list()
    for cipher in ciphers:
        lengths.append(len(cipher))

    concatinated_cipher = ByteData()
    for cipher in ciphers:
        concatinated_cipher += cipher[:min(lengths)]

    xor = RepeatingXor(concatinated_cipher, EnglishScore())
    xor.min_key_size = min(lengths)
    xor.max_key_size = min(lengths) + 1

    key = xor.break_multiple_byte_key()
    data = concatinated_cipher.repeating_key_xor(key)
    for num in range(0, len(concatinated_cipher), min(lengths)):
        print(data[num:num+min(lengths)].get_data())
