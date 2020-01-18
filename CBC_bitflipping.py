#!/usr/bin/env python3
from crypto_tools import CBCBitFlippingAttack
from crypto_tools import ByteData
from crypto_tools import UTF8Converter
from crypto_tools import HexConverter


def bitflip():
    """
    evil input:
         A  A  A  A  A  ;  a  d  m  i  n  =  t  r  u  e
        00 00 00 00 00 01 00 00 00 00 00 01 00 00 00 00
    """
    backend = CBCBitFlippingAttack()

    user_input = 'AAAAA;admin=true'
    user_data = ByteData(user_input, UTF8Converter())

    bitflip = '00000000000100000000000100000000'
    bitflip_data = ByteData(bitflip, HexConverter())

    xor_data = user_data ^ bitflip_data

    cipher = backend.encrypt(xor_data.encode(UTF8Converter()))
    prefix_cipher = cipher[:16]
    postfix_cipher = cipher[32:]
    evil_block = cipher[16:32] ^ bitflip_data

    evil_cihper = prefix_cipher + evil_block + postfix_cipher

    evil_cleartext = backend.decrypt(evil_cihper)
    print(evil_cleartext['admin'])


if __name__ == '__main__':
    for num in range(50):
        bitflip()
