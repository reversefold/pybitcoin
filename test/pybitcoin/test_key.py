import unittest

from pybitcoin import key


class TestAddressMethods(unittest.TestCase):
    def test_address_from_pk_hash(self):
        self.assertEquals(
            key.address_from_pk_hash(
                '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B'),
            '\x00\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B\xe6\xf2\xf5Y')

    def test_base58_encode_address(self):
        self.assertEquals(
            key.base58_encode(
                key.address_from_pk_hash(
                    '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B')),
            '1NJHiNy5CS2heskf6bx3VuHm9zjXTGdtSt')

    def test_base58_decode_address(self):
        self.assertEquals(
            key.base58_decode('1NJHiNy5CS2heskf6bx3VuHm9zjXTGdtSt'),
            key.address_from_pk_hash(
                '\xe9\x9f\xaa\x1b\x12\x8f\x13w\x8d"#\xa9\xd1\xd3~\x88\x92\x0b]B'))

    def test_address_from_pubkey(self):
        self.assertEquals(key.address_from_pubkey('\x04\x01\x00\xb9\xce\x1a\xcfg\x16\xa2\xd6Os\xb2\xa6%\xf2\xc1\x0c\xe9\x19\xe5(\xa9?`Z\xf1\xd7=M[AY\x99\xff\xde\xf8\x89\xd9m\xccB"\x0e\xd9ys\xb0S{k\x95\xa3\xec\\\xa2\xaf\x96B`\x1fK\x12\xe8'),
                          '\x00\x87\x8b\xb12\x12\x0c\xcb\x1e\xd0\x7f\x87\xb5\xf6Q6\t\xb1\xff\xe2\xcc\x9f\xb2^\xc1')

    def test_address_from_compressed_pubkey(self):
        self.assertEquals(key.address_from_pubkey('\x02\x01\x00\xb9\xce\x1a\xcfg\x16\xa2\xd6Os\xb2\xa6%\xf2\xc1\x0c\xe9\x19\xe5(\xa9?`Z\xf1\xd7=M[A'),
                          '\x00\xc5\xf0\xf9\xb63\x08+b\xfe\xb5 \xb8\xea<L\x12)\x1c\xaae\xe7\xf6\xf30')

    def test_natural_to_string_negative(self):
        with self.assertRaises(TypeError):
            key.natural_to_string(-1)

    def test_natural_to_string_odd_length(self):
        self.assertEquals(key.natural_to_string(2), '\x02')

    def test_decode_privkey(self):
        self.assertEqual(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'),
            int('7F3B6EAF1C8C3BFD8B0727B979746A932B6B9F9489898379DD65C1E3CCC3B4DF', 16))

    def test_encode_privkey(self):
        self.assertEqual(
            key.encode_privkey(int('7F3B6EAF1C8C3BFD8B0727B979746A932B6B9F9489898379DD65C1E3CCC3B4DF', 16)),
            '5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps')

    def test_priv_to_pub(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(pub.x(), 106166571357547839921127737825237030169011311004864544123912774005363869489531L)
        self.assertEquals(pub.y(), 25551918952383289921400942500183155031311393141491670111210077721682692525744L)

    def test_encode_pub(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(key.encode_pub(pub), '04EAB82662C4A329F573E96801CCFCF9337446D2742EFDC5A6E8EA8F617AD0197B387DDFA56684EF2F4E2325F298F5F418ADCB00F560B75F4DEEAF90ABD5A3CEB0'.decode('hex'))

    def test_encode_pub_compressed(self):
        pub = key.priv_to_pub(
            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))
        self.assertEquals(key.encode_pub_compressed(pub), '02EAB82662C4A329F573E96801CCFCF9337446D2742EFDC5A6E8EA8F617AD0197B'.decode('hex'))

    def test_priv_key_to_address(self):
        self.assertEquals(
            key.base58_encode(
                key.address_from_pubkey(
                    key.encode_pub(
                        key.priv_to_pub(
                            key.decode_privkey('5JnKZDMUAddiGgFjWiHNVrX5pxGcEJ1miscs2Xhy7f9BrGffrps'))))),
            '1EEaiQ4DXxf8seerjdNR69by8pwZeBJ6mJ')
