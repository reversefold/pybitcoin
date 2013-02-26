import ecdsa
from hashlib import sha256, new as new_hash
import random
import struct


base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def natural_to_string(n, alphabet=None):
    if n < 0:
        raise TypeError('n must be a natural')
    if alphabet is None:
        s = ('%x' % (n,)).lstrip('0')
        if len(s) % 2:
            s = '0' + s
        return s.decode('hex')
    else:
        assert len(set(alphabet)) == len(alphabet)
        res = []
        while n:
            n, x = divmod(n, len(alphabet))
            res.append(alphabet[x])
        res.reverse()
        return ''.join(res)


def string_to_natural(s, alphabet=None):
    if alphabet is None:
        assert not s.startswith('\x00')
        return int(s.encode('hex'), 16) if s else 0
    else:
        assert len(set(alphabet)) == len(alphabet)
        assert not s.startswith(alphabet[0])
        return sum(alphabet.index(char) * len(alphabet)**i for i, char in enumerate(reversed(s)))


def base58_encode(bindata):
    bindata2 = bindata.lstrip(chr(0))
    return base58_alphabet[0]*(len(bindata) - len(bindata2)) + natural_to_string(string_to_natural(bindata2), base58_alphabet)


def base58_decode(b58data):
    b58data2 = b58data.lstrip(base58_alphabet[0])
    return chr(0)*(len(b58data) - len(b58data2)) + natural_to_string(string_to_natural(b58data2, base58_alphabet))


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


def address_from_pubkey(bytes):
    return address_from_pk_hash(new_hash('ripemd160', sha256(bytes).digest()).digest())


def address_from_pk_hash(bytes):
    ext_hash = '\x00' + bytes
    return ext_hash + sha256(sha256(ext_hash).digest()).digest()[:4]
