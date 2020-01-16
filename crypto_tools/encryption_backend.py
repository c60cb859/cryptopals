#!/usr/bin/env python3
import string
import random

from .byte_data import ByteData
from .aes import AesECB
from .data_conversion import Base64Converter
from .data_conversion import UTF8Converter
from .data_conversion import HexConverter


class EncryptionBackend:
    def __init__(self):
        pass

    def encrypt(self, cleartext):
        pass


class ByteAtATimeECBSimple(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_printable_key()
        self._text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' +\
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        self._data = ByteData(self._text, Base64Converter())

    def _generate_printable_key(self):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(self.key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

    def encrypt(self, cleartext):
        known_data = ByteData(cleartext, UTF8Converter())
        cleartext_data = known_data + self._data

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher


class EncryptedCookieGenerator(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_printable_key()

    def _generate_printable_key(self):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(self.key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

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
        cipher_data = ByteData(cookie, HexConverter())
        cipher = AesECB(cipher_data)
        cleartext = cipher.decrypt(self._key)

        return cleartext


class ByteAtATimeECBHarder(EncryptionBackend):
    def __init__(self):
        self.key_size = 16
        self._key = self._generate_printable_key()
        self._prefix = self._generate_random_prefix()
        self._text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll' +\
                     'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        self._data = ByteData(self._text, Base64Converter())

    def _generate_printable_key(self):
        key = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(self.key_size):
            key += random.choice(printable_char)

        return ByteData(key, UTF8Converter())

    def _generate_random_prefix(self):
        prefix = ''
        printable_char = string.ascii_letters + string.digits + string.punctuation
        for num in range(random.randint(0, self.key_size)):
            prefix += random.choice(printable_char)

        return ByteData(prefix, UTF8Converter())

    def encrypt(self, cleartext):
        known_data = ByteData(cleartext, UTF8Converter())
        cleartext_data = self._prefix + known_data + self._data

        cleartext = AesECB(cleartext_data.pkcs7_pad(self.key_size))
        cipher = cleartext.encrypt(self._key)

        return cipher
