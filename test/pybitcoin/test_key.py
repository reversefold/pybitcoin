import binascii
import unittest

from pybitcoin import key
from pybitcoin import byte_util


class TestBase58(unittest.TestCase):
    def test_base58_encode_zero(self):
        self.assertEquals(byte_util.base58_encode('\x00'), '1')

    def test_base58_decode_zero(self):
        self.assertEquals(byte_util.base58_decode('1'), '\x00')

    def test_base58_encode_address(self):
        self.assertEquals(
            byte_util.base58_encode(
                key.address_from_pk_hash(
                    '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B')),
            '1NJHiNy5CS2heskf6bx3VuHm9zjXTGdtSt')

    def test_base58_decode_address(self):
        self.assertEquals(
            byte_util.base58_decode('1NJHiNy5CS2heskf6bx3VuHm9zjXTGdtSt'),
            key.address_from_pk_hash(
                '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B'))


class TestAddressMethods(unittest.TestCase):
    def test_address_from_pk_hash(self):
        self.assertEquals(
            key.address_from_pk_hash(
                '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B'),
            '\x00\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B\xe6\xf2\xf5Y')

    def test_address_from_pubkey(self):
        self.assertEquals(
            key.address_from_pubkey(
                '\x04\x01\x00\xb9\xce\x1a\xcfg\x16\xa2\xd6Os\xb2\xa6%\xf2\xc1\x0c\xe9\x19\xe5(\xa9?'
                '`Z\xf1\xd7=M[AY\x99\xff\xde\xf8\x89\xd9m\xccB"\x0e\xd9ys\xb0S{k\x95\xa3\xec\\\xa2'
                '\xaf\x96B`\x1fK\x12\xe8'),
            '\x00\x87\x8b\xb12\x12\x0c\xcb\x1e\xd0\x7f\x87\xb5\xf6Q6\t\xb1\xff\xe2\xcc\x9f\xb2^\xc1'
        )

    def test_address_from_compressed_pubkey(self):
        self.assertEquals(
            key.address_from_pubkey(
                '\x02\x01\x00\xb9\xce\x1a\xcfg\x16\xa2\xd6Os\xb2\xa6%\xf2\xc1\x0c\xe9\x19\xe5(\xa9?'
                '`Z\xf1\xd7=M[A'),
            '\x00\xc5\xf0\xf9\xb63\x08+b\xfe\xb5 \xb8\xea<L\x12)\x1c\xaae\xe7\xf6\xf30')


class TestKey(unittest.TestCase):
    def test_decode_privkey(self):
        self.assertEqual(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'),
            int('7F3B6EAF1C8C3BFD8B0727B979746A932B6B9F9489898379DD65C1E3CCC3B4DF', 16))

    def test_decode_privkey_checksum_mismatch(self):
        priv_enc = '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'
        priv = byte_util.base58_decode(priv_enc)[:-1] + '\x42'
        with self.assertRaises(key.Error):
            key.decode_privkey(byte_util.base58_encode(priv))

    def test_decode_privkey_bad_version(self):
        priv_enc = '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'
        priv = '\x08' + byte_util.base58_decode(priv_enc)[1:]
        with self.assertRaises(key.Error):
            key.decode_privkey(byte_util.base58_encode(priv))

    def test_encode_privkey(self):
        self.assertEqual(
            key.encode_privkey(
                int('7F3B6EAF1C8C3BFD8B0727B979746A932B6B9F9489898379DD65C1E3CCC3B4DF', 16)),
            '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps')

    def test_encode_privkey_compressed(self):
        self.assertEqual(
            key.encode_privkey_compressed(
                int('7F3B6EAF1C8C3BFD8B0727B979746A932B6B9F9489898379DD65C1E3CCC3B4DF', 16)),
            'L1V2uBXLuWh3ACG2e9DFtMZnJewtVg6QPpRHokXpgPM8tGd9yBbX')

    def test_encode_privkey2(self):
        priv = 3566362552192297244228444858243043761472313190548212544975902619635471184649L
        self.assertEqual(
            key.encode_privkey(priv),
            '5Hskz9wmd3fnTPVnmPhaLtvaumjQU9ycCYWwkiRPgdQ1B4PcoAf')

    def test_encode_privkey2_compressed(self):
        priv = 3566362552192297244228444858243043761472313190548212544975902619635471184649L
        self.assertEqual(
            key.encode_privkey_compressed(priv),
            'KwV39GUjx6nBdUJ4zwC6ApBWfvSAarcrMx7Afwpf7ueXm5Wuc1r2')

    def test_priv_to_pub(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(
            pub.x(),
            106166571357547839921127737825237030169011311004864544123912774005363869489531L)
        self.assertEquals(
            pub.y(),
            25551918952383289921400942500183155031311393141491670111210077721682692525744L)

    def test_encode_pub(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(
            key.encode_pub(pub),
            binascii.unhexlify('04EAB82662C4A329F573E96801CCFCF9337446D2742EFDC5A6E8EA8F617AD0197B387DDFA'
                               '56684EF2F4E2325F298F5F418ADCB00F560B75F4DEEAF90ABD5A3CEB0'))

    def test_encode_pub_compressed(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(
            key.encode_pub_compressed(pub),
            binascii.unhexlify('02EAB82662C4A329F573E96801CCFCF9337446D2742EFDC5A6E8EA8F617AD0197B'))

    def test_priv_key_to_address(self):
        self.assertEquals(
            byte_util.base58_encode(
                key.address_from_pubkey(
                    key.encode_pub(
                        key.priv_to_pub(
                            key.decode_privkey(
                                '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))))),
            '1EEaiQ4DXxf8seerjdNR69by8pwZeBJ6mJ')
        self.assertEquals(
            byte_util.base58_encode(
                key.priv_to_address(
                    key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))),
            '1EEaiQ4DXxf8seerjdNR69by8pwZeBJ6mJ')

    def test_priv_key_to_address_compressed(self):
        self.assertEquals(
            byte_util.base58_encode(
                key.address_from_pubkey(
                    key.encode_pub_compressed(
                        key.priv_to_pub(
                            key.decode_privkey(
                                '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))))),
            '19ufHMz2mhGHhSSQEmqBsqZUTMHB79urP9')
        self.assertEquals(
            byte_util.base58_encode(
                key.priv_to_address_compressed(
                    key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))),
            '19ufHMz2mhGHhSSQEmqBsqZUTMHB79urP9')

    def test_priv_addition_is_pub_addition(self):
        # adding private keys gives the same address as adding their public keys
        key1 = key.generate_priv()
        key2 = key.generate_priv()
        self.assertEquals(
            byte_util.base58_encode(key.priv_to_address(key1 + key2)),
            byte_util.base58_encode(
                key.address_from_pubkey(
                    key.encode_pub(key.priv_to_pub(key1) + key.priv_to_pub(key2)))))

    def test_decode_pub_encode_pub_symmetric(self):
        pub = binascii.unhexlify('04EAB82662C4A329F573E96801CCFCF9337446D2742EFDC5A6E8EA8F617AD0197B387DDFA'
                                 '56684EF2F4E2325F298F5F418ADCB00F560B75F4DEEAF90ABD5A3CEB0')
        self.assertEquals(key.encode_pub(key.decode_pub(pub)), pub)

    def test_decode_pub_compressed(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(key.decode_pub(key.encode_pub_compressed(pub)), pub)

        for _ in xrange(100):
            print _
            priv = key.generate_priv()
            pub = key.priv_to_pub(priv)
            self.assertEquals(key.decode_pub(key.encode_pub_compressed(pub)), pub)
