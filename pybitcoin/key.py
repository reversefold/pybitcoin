import ecdsa
from hashlib import sha256, new as new_hash
import random
import struct


base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class Error(Exception):
    pass


def base58_chars(num):
    while num > 0:
        (num, remainder) = divmod(num, 58)
        yield base58_alphabet[remainder]


def base58_encode(bytes):
    leading_zeros = 0
    while leading_zeros < len(bytes) and bytes[leading_zeros] == '\x00':
        leading_zeros += 1
    num = int(bytes.encode('hex'), 16)
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
    return (leading_zeros * '\x00') + decoded_hex.decode('hex')


def decode_privkey(priv):
    bytes = base58_decode(priv)
    version = bytes[0]
    if version != '\x80':
        raise Error('Version (%r) != \x80' % (version,))
    checksum = bytes[-4:]
    hash = sha256(sha256(bytes[:-4]).digest()).digest()
    if hash[:4] != checksum:
        raise Error('Checksum mismatch')
    return int(bytes[1:-4].encode('hex'), 16)


def encode_privkey(priv):
    bytes = '\x80' + hex(priv)[2:].rstrip('L').decode('hex')
    hash = sha256(sha256(bytes).digest()).digest()
    return base58_encode(bytes + hash[:4])


def encode_privkey_compressed(priv):
    bytes = '\x80' + hex(priv)[2:].rstrip('L').decode('hex') + '\x01'
    hash = sha256(sha256(bytes).digest()).digest()
    return base58_encode(bytes + hash[:4])


# secp256k1
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = g = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
randrange = random.SystemRandom().randrange
secp256k1 = ecdsa.curves.Curve(
    "secp256k1",
    curve_secp256k1,
    generator_secp256k1,
    (1, 3, 132, 0, 10)
    )
# add this to the list of official NIST curves.
ecdsa.curves.curves.append(secp256k1)


def priv_to_pub(priv):
    return secp256k1.generator * priv


def encode_bigint(b):
    return struct.pack('>QQQQ',
                       (b >> 192) & 0xffffffffffffffff,
                       (b >> 128) & 0xffffffffffffffff,
                       (b >> 64) & 0xffffffffffffffff,
                       b & 0xffffffffffffffff)


def encode_pub(pub):
    return '\x04%s%s' % (encode_bigint(pub.x()), encode_bigint(pub.y()))


def encode_pub_compressed(pub):
    return '%s%s' % ('\x02' if pub.y() % 2 == 0 else '\x03', encode_bigint(pub.x()))


def address_from_pubkey(bytes):
    return address_from_pk_hash(new_hash('ripemd160', sha256(bytes).digest()).digest())


def address_from_pk_hash(bytes):
    ext_hash = '\x00' + bytes
    return ext_hash + sha256(sha256(ext_hash).digest()).digest()[:4]


def priv_to_address(priv):
    return address_from_pubkey(
        encode_pub(
            priv_to_pub(priv)))


def priv_to_address_compressed(priv):
    return address_from_pubkey(
        encode_pub_compressed(
            priv_to_pub(priv)))


def generate_priv():
    return randrange(1, secp256k1.order)
