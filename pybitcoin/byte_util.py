import binascii
from hashlib import sha256
import struct


base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class Error(Exception):
    pass


class ParseError(Error):
    pass


def fmt_w_size(fmt):
    return (fmt, struct.calcsize(fmt))


def splitn(bytes, n):
    if len(bytes) < n:
        raise ParseError('Expected %r+ bytes, got %r: %r' % (n, len(bytes), bytes))
    return bytes[:n], bytes[n:]


def parse(bytes, fmt):
    (bit, bytes) = splitn(bytes, fmt[1])
    return (struct.unpack(fmt[0], bit), bytes)


def base58_chars(num):
    while num > 0:
        (num, remainder) = divmod(num, 58)
        yield base58_alphabet[remainder]


def base58_encode(bytes):
    leading_zeros = 0
    while leading_zeros < len(bytes) and bytes[leading_zeros] == '\x00':
        leading_zeros += 1
    num = int(binascii.hexlify(bytes), 16)
    encoded = '%s%s' % (
        ''.join(base58_chars(num)),
        base58_alphabet[0] * leading_zeros)
    return encoded[::-1]


def base58_decode(bytes):
    leading_zeros = 0
    while leading_zeros < len(bytes) and bytes[leading_zeros] == '1':
        leading_zeros += 1
    bytes = bytes[leading_zeros:]
    num = 0
    for i in xrange(len(bytes)):
        num = num * 58 + base58_alphabet.index(bytes[i])
    if num > 0:
        decoded_hex = hex(num)[2:].rstrip('L')
        if len(decoded_hex) % 2:
            decoded_hex = '0' + decoded_hex
    else:
        decoded_hex = ''
    return (leading_zeros * '\x00') + binascii.unhexlify(decoded_hex)


def base58_encode_checksum(raw):
    hash = sha256(sha256(raw).digest()).digest()
    return base58_encode(raw + hash[:4])


def base58_decode_checksum(enc):
    raw = base58_decode(enc)
    checksum = raw[-4:]
    data = raw[:-4]
    hash = sha256(sha256(data).digest()).digest()
    if hash[:4] != checksum:
        raise Error('Checksum mismatch')
    return data


# while clever, these are equivalent to encode_bigint and decode_bigint and much slower
#def long_to_bytes(num):
#    return binascii.unhexlify(hex(num)[2:].rstrip('L').zfill(64))
#
#
#def bytes_to_long(raw):
#    return int(binascii.hexlify(raw), 16)

