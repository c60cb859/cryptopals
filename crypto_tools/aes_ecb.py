#!/bin/python3

from Crypto.Cipher import AES


def enc_aes_ecb(key, cleartext):
    algrorithm = AES.new(key, AES.MODE_ECB)
    cipher = algrorithm.encrypt(cleartext)

    return cipher


def dec_aes_ecb(key, cipher):
    algrorithm = AES.new(key, AES.MODE_ECB)
    cleartext = algrorithm.decrypt(cipher)

    return cleartext
