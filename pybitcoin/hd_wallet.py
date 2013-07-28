#!/usr/bin/env python
from hashlib import sha256, sha512, new as new_hash
import hmac
import struct

from pybitcoin.byte_util import base58_encode_checksum, base58_decode_checksum
from pybitcoin.key import _decode_pub_compressed, encode_pub_compressed, encode_bigint, decode_bigint, priv_to_pub, secp256k1


def hmac_sha512(key, msg):
    return hmac.new(key, msg, sha512)


class Error(Exception):
    pass


class HDKey(object):
    def __init__(
        self, key, chain_code, version,
        depth=0, child_number=0, parent_fingerprint='\x00\x00\x00\x00'
    ):
        self.version = version
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.child_number = child_number
        self.parent_fingerprint = parent_fingerprint

    def fingerprint(self):
        raise TypeError('unimplemented')

    def serialized_key(self):
        raise TypeError('unimplemented')

    def serialized(self):
        return ''.join([
            self.version,
            struct.pack('>B', self.depth),
            self.parent_fingerprint,
            struct.pack('>L', self.child_number),
            self.chain_code,
            self.serialized_key()
        ])

    def encoded(self):
        return base58_encode_checksum(self.serialized())

    @classmethod
    def decode(cls, enc):
        return cls.unserialize(base58_decode_checksum(enc))

    @classmethod
    def unserialize(cls, raw):
        version = raw[:4]
        depth = struct.unpack('>B', raw[4:5])[0]
        parent_fingerprint = raw[5:9]
        child_number = struct.unpack('>L', raw[9:13])[0]
        chain_code = raw[13:45]
        raw_key = raw[45:]
        if version in VERSION_KEY_MAP:
            key_cls = VERSION_KEY_MAP[version]
            key = key_cls.unserialize_key(raw_key)
            return key_cls(key, chain_code, depth, child_number, parent_fingerprint, key_cls.V_T[version])
        else:
            raise TypeError('version not recognized (%r)' % (version,))

    @classmethod
    def unserialize_key(cls, key):
        raise TypeError('unimplemented')


class HDPrivKey(HDKey):
    T_V = {True: '\x04\x35\x83\x94', False: '\x04\x88\xAD\xE4'}

    def __init__(self, key, chain_code, depth=0, child_number=0, parent_fingerprint='\x00\x00\x00\x00', testnet=False):
        super(HDPrivKey, self).__init__(
            key, chain_code,
            self.T_V[testnet],
            depth, child_number, parent_fingerprint)

    def serialized_key(self):
        return '\x00' + encode_bigint(self.key)

    def derive_child(self, i):
        high_bit = i & 0x80000000
        if high_bit:
            I = hmac_sha512(self.chain_code, '\x00' + encode_bigint(self.key) + struct.pack('>L', i)).digest()
        else:
            I = hmac_sha512(self.chain_code, encode_pub_compressed(priv_to_pub(self.key)) + struct.pack('>L', i)).digest()
        IL = decode_bigint(I[:32])
        if IL >= secp256k1.order:
            raise Error('invalid key')
        IR = I[32:]
        ki = (IL + self.key) % secp256k1.order
        if ki == 0:
            raise Error('invalid key')
        ci = IR
        return HDPrivKey(ki, ci, self.depth + 1, i, self.fingerprint(), self.V_T[self.version])

    def fingerprint(self):
        return self.pub().fingerprint()

    def pub(self):
        return HDPubKey(priv_to_pub(self.key), self.chain_code, self.depth, self.child_number, self.parent_fingerprint, self.V_T[self.version])

    @classmethod
    def unserialize_key(cls, raw):
        key_type = raw[0]
        if key_type != '\x00':
            raise TypeError('key_type should be \\x00, not %r' % (key_type,))
        return decode_bigint(raw[1:])


class HDPubKey(HDKey):
    T_V = {True: '\x04\x35\x87\xCF', False: '\x04\x88\xB2\x1E'}

    def __init__(self, key, chain_code, depth=0, child_number=0, parent_fingerprint='\x00\x00\x00\x00', testnet=False):
        super(HDPubKey, self).__init__(
            key, chain_code,
            self.T_V[testnet],
            depth, child_number, parent_fingerprint)

    def serialized_key(self):
        return encode_pub_compressed(self.key)

    def fingerprint(self):
        return new_hash('ripemd160', sha256(self.serialized_key()).digest()).digest()[:4]

    def derive_child(self, i):
        if i & 0x80000000:
            raise Error('Invalid i (%r)' % (i,))
        else:
            I = hmac_sha512(self.chain_code, encode_pub_compressed(self.key) + struct.pack('>L', i)).digest()
        IL = decode_bigint(I[:32])
        if IL >= secp256k1.order:
            raise Error('invalid key')
        IR = I[32:]

        Ki = IL * secp256k1.generator + self.key
        #if Ki == INFINITY:
        #    raise Error('invalid key')
        ci = IR
        return HDPubKey(Ki, ci, self.depth + 1, i, self.fingerprint(), self.V_T[self.version])

    @classmethod
    def unserialize_key(cls, raw):
        return _decode_pub_compressed(raw)


VERSION_KEY_MAP = {}
for cls in [HDPubKey, HDPrivKey]:
    cls.V_T = {v: k for k, v in cls.T_V.iteritems()}
    cls.VERSIONS = cls.T_V.values()
    for version in cls.VERSIONS:
        VERSION_KEY_MAP[version] = cls

