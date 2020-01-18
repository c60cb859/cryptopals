#!/usr/bin/env python3
import string
import random

from .byte_data import ByteData
from .aes import AesECB
from .aes import AesCBC
from .data_conversion import Base64Converter
from .data_conversion import UTF8Converter


class EncryptionBackend:
    def __init__(self):
        pass

    def _generate_random_printable_key(self, key_size):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

    def encrypt(self, cleartext):
        pass


class ByteAtATimeECBSimple(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_random_printable_key(self.key_size)
        self._text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' +\
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        self._data = ByteData(self._text, Base64Converter())

    def encrypt(self, cleartext):
        known_data = ByteData(cleartext, UTF8Converter())
        cleartext_data = known_data + self._data

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher


class EncryptedCookieGenerator(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_random_printable_key(self.key_size)

    def _kv_serialize(self, dictionary):
        """Serialize a dictionary to a key value string"""
        serialized_string = ''
        for key in dictionary:
            element = key + '=' + dictionary[key] + '&'
            serialized_string += element

        return serialized_string[:-1]

    def _kv_deserialize(self, serialized_string):
        """Deserialize a key value string to a dictionary"""
        output = {}
        pairs = serialized_string.split('&')

        for pair in pairs:
            key, value = pair.split('=')
            output[key] = value

        return output

    def _profile_for(self, email):
        user_profile = {'email': '', 'uid': '10', 'role': 'user'}
        stripped_email = email.replace('&', '').replace('=', '')
        user_profile['email'] = stripped_email

        return self._kv_serialize(user_profile)

    def encrypt(self, cleartext):
        profile = self._profile_for(cleartext)
        cleartext_data = ByteData(profile, UTF8Converter())

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher

    def decrypt(self, cookie):
        cipher = AesECB(cookie)
        cleartext_data_padded = cipher.decrypt(self._key)
        cleartext_data = cleartext_data_padded.pkcs7_pad_remove()
        cleartext = cleartext_data.encode(UTF8Converter())

        dictornary = self._kv_deserialize(cleartext)

        return dictornary


class ByteAtATimeECBHarder(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_random_printable_key(self.key_size)
        self._prefix = self._generate_random_prefix()
        self._text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' +\
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        self._data = ByteData(self._text, Base64Converter())

    def _generate_random_prefix(self):
        prefix = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(random.randint(0, self.key_size*3)):
            prefix += random.choice(printable_char)

        return ByteData(prefix, UTF8Converter())

    def encrypt(self, cleartext):
        known_data = ByteData(cleartext, UTF8Converter())
        cleartext_data = self._prefix + known_data + self._data

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher


class CBCBitFlippingAttack(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_random_printable_key(self.key_size)
        self._prefix = 'comment1=cooking%20MCs;userdata='
        self._postfix = ';comment2=%20like%20a%20pound%20of%20bacon'

    def _kv_deserialize(self, serialized_string):
        """Deserialize a key value string to a dictionary"""
        output = {}
        pairs = serialized_string.split(';')

        for pair in pairs:
            try:
                key, value = pair.split('=')
            except ValueError:
                pass
            else:
                output[key] = value

        return output

    def _sanitize_input(self, cleartext):
        stripped_input = cleartext.replace(';', '').replace('=', '')

        return stripped_input

    def encrypt(self, cleartext):
        stripped_input = self._sanitize_input(cleartext)
        cleartext_input = self._prefix + stripped_input + self._postfix
        cleartext_data = ByteData(cleartext_input, UTF8Converter())

        cleartext = AesCBC(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher

    def decrypt(self, cipher):
        cipher = AesCBC(cipher)
        cleartext = cipher.decrypt(self._key)
        cleartext_no_pad = cleartext.pkcs7_pad_remove()
        output = self._kv_deserialize(cleartext_no_pad.encode(UTF8Converter()))

        return output


class CBCPaddingOracle(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_random_printable_key(self.key_size)
        self._data = self._pick_random_string()

    def _pick_random_string(self):
        strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                   'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                   'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                   'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                   'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                   'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                   'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                   'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                   'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                   'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
        string = random.choice(strings)

        return ByteData(string, Base64Converter())

    def encrypt(self):
        crypto = AesCBC(self._data.pkcs7_pad(self.key_size))
        cipher = crypto.encrypt(self._key)

        return cipher

    def decrypt(self, cipher):
        cipher = AesCBC(cipher)
        cleartext = cipher.decrypt(self._key)
        try:
            cleartext.pkcs7_pad_remove()
        except Exception:
            return False
        else:
            return True
