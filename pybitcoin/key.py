import ecdsa
import random
import struct

# secp256k1
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp (_p, _a, _b)
generator_secp256k1 = g = ecdsa.ellipticcurve.Point (curve_secp256k1, _Gx, _Gy, _r)
randrange = random.SystemRandom().randrange
secp256k1 = ecdsa.curves.Curve (
    "secp256k1",
    curve_secp256k1,
    generator_secp256k1,
    (1, 3, 132, 0, 10)
    )
# add this to the list of official NIST curves.
ecdsa.curves.curves.append (secp256k1)


def priv_to_pub(priv):
    return secp256k1.generator * priv


def encode_bigint(b):
    return struct.pack('>QQQQ', (b >> 192) & 0xffffffffffffffff, (b >> 128) & 0xffffffffffffffff, (b >> 64) & 0xffffffffffffffff, b & 0xffffffffffffffff)


def encode_pub(pub):
    return '\x04%s%s' % (encode_bigint(pub.x()), encode_bigint(pub.y()))


def encode_pub_compressed(pub):
    return '%s%s' % ('\x02' if pub.y() % 2 == 0 else '\x03', encode_bigint(pub.x()))
