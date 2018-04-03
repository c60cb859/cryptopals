import base64
import codecs


def hex_to_bytes(hex_string):
    byte_data = bytearray.fromhex(hex_string)
    return byte_data


def base64_to_bytes(base64_string):
    byte_data = base64.b64decode(base64_string)
    return byte_data


def utf8_to_bytes(utf8_string):
    byte_data = utf8_string.encode('utf-8')
    return byte_data


def int_to_single_byte(integer):
    if integer > 255:
        raise ValueError('input to large')
    single_byte = bytes([integer])
    return single_byte


def bytes_to_hex(byte_data):
    hex_string = byte_data.hex()
    return hex_string


def bytes_to_base64(byte_data):
    base64_string = codecs.encode(byte_data, 'base64')
    utf8_printable = base64_string.decode('utf-8')[:-1]
    return utf8_printable


def bytes_to_utf8(byte_data):
    utf8_string = byte_data.decode('latin-1')
    return utf8_string
