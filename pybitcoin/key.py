import ecdsa
from hashlib import sha256, new as new_hash
import random
import struct

from pybitcoin import msqr
from pybitcoin.byte_util import Error, base58_encode_checksum, base58_decode_checksum


def decode_privkey(priv):
    raw = base58_decode_checksum(priv)
    version = raw[0]
    if version != '\x80':
        raise Error('Version (%r) != \x80' % (version,))
    return decode_bigint(raw[1:])


def encode_privkey(priv):
    raw = '\x80' + encode_bigint(priv)
    return base58_encode_checksum(raw)


def encode_privkey_compressed(priv):
    raw = '\x80' + encode_bigint(priv) + '\x01'
    return base58_encode_checksum(raw)


# secp256k1
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

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


BIGINT_ENCODING = '>QQQQ'
BIGINT_BYTES = struct.calcsize(BIGINT_ENCODING)
QMASK = 0xffffffffffffffff

def encode_bigint(b):
    return struct.pack(BIGINT_ENCODING,
                       (b >> 192) & QMASK,
                       (b >> 128) & QMASK,
                       (b >> 64) & QMASK,
                       b & QMASK)


def decode_bigint(bytes):
    (a, b, c, d) = struct.unpack(BIGINT_ENCODING, bytes)
    return (a << 192) | (b << 128) | (c << 64) | d


def encode_pub(pub):
    return '\x04%s%s' % (encode_bigint(pub.x()), encode_bigint(pub.y()))


def _decode_pub(bytes):
    if bytes[0] != '\x04':
        raise Error('byte 0 should be 0x04')
    x = decode_bigint(bytes[1:BIGINT_BYTES + 1])
    y = decode_bigint(bytes[BIGINT_BYTES + 1:])
    return ecdsa.ellipticcurve.Point(
        curve_secp256k1, x, y, secp256k1.order)


def _decode_pub_compressed(bytes):
    if bytes[0] not in ['\x02', '\x03']:
        raise Error('first byte not x02 or \x03')
    x = decode_bigint(bytes[1:])
    alpha = (x * x * x  + curve_secp256k1.a() * x + curve_secp256k1.b()) % curve_secp256k1.p()
    beta = msqr.modular_sqrt(alpha, curve_secp256k1.p())
    y = beta if (beta - ord(bytes[0])) % 2 == 0 else curve_secp256k1.p() - beta
    return ecdsa.ellipticcurve.Point(
        curve_secp256k1, x, y, secp256k1.order)


def decode_pub(bytes):
    if bytes[0] == '\x04':
        return _decode_pub(bytes)
    elif bytes[0] in ['\x02', '\x03']:
        return _decode_pub_compressed(bytes)


def encode_pub_compressed(pub):
    return '%s%s' % ('\x02' if pub.y() % 2 == 0 else '\x03', # chr(2 + (pub.y() & 1))
                     encode_bigint(pub.x()))


def address_from_pubkey(bytes):
    return address_from_pk_hash(new_hash('ripemd160', sha256(bytes).digest()).digest())


def address_from_pk_hash(bytes):
    ext_hash = '\x00' + bytes
    return ext_hash + sha256(sha256(ext_hash).digest()).digest()[:4]


def pub_to_address(pub):
    return address_from_pubkey(encode_pub(pub))


def priv_to_address(priv):
    return pub_to_address(priv_to_pub(priv))


def pub_to_address_compressed(pub):
    return address_from_pubkey(encode_pub_compressed(pub))


def priv_to_address_compressed(priv):
    return pub_to_address_compressed(priv_to_pub(priv))


def generate_priv():
    return randrange(1, secp256k1.order)
