import binascii
import unittest

from pybitcoin import hd_wallet


class TestHDWallet(unittest.TestCase):
    def test_generate_128_bits(self):
        seed = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')
        expected = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP'
                    'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        key = hd_wallet.HDPrivKey.generate_master(seed)
        self.assertEqual(key.encoded(), expected)

    def test_generate_512_bits(self):
        seed = binascii.unhexlify(
            'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2'
            '9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
        expected = ('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtAL'
                    'Gdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
        key = hd_wallet.HDPrivKey.generate_master(seed)
        self.assertEqual(key.encoded(), expected)

    def test_generate_random(self):
        hd_wallet.HDPrivKey.generate_master()

    def test_generate_random_128_bytes(self):
        hd_wallet.HDPrivKey.generate_master(num_random_bytes=128)

    def test_decode_encode_priv(self):
        key = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP'
               'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        self.assertEquals(hd_wallet.HDKey.decode(key).encoded(), key)

    def test_decode_encode_pub(self):
        key = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe'
               'PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
        self.assertEquals(hd_wallet.HDKey.decode(key).encoded(), key)

    def test_m_priv_to_pub(self):
        key = hd_wallet.HDKey.decode(
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP'
            'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        self.assertEqual(
            key.pub().encoded(),
            'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe'
            'PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')

    def test_priv_to_pub_2(self):
        key = hd_wallet.HDKey.decode(
          'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU'
          'xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7')
        self.assertEqual(key.pub().encoded(),
          'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEj'
          'WgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw')

    def test_m_0p_priv(self):
        raw_key = ('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP'
                   'qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        expected = ('xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU'
                    'xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7')
        key = hd_wallet.HDKey.decode(raw_key)
        child = key.derive_child(hd_wallet.PUBLIC_DERIVATION_BIT)
        self.assertEqual(
            child.encoded(),
            expected)

        expected = ('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEj'
                    'WgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw')
        self.assertEqual(child.pub().encoded(), expected)

    def test_private_m_0_public_derivation(self):
        encoded = ('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtAL'
                   'Gdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
        expected = ('xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQ'
                    'RUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt')
        key = hd_wallet.HDKey.decode(encoded)
        child = key.derive_child(0)
        self.assertEqual(
            child.encoded(),
            expected)

    def test_public_m_0_public_derivation_from_priv(self):
        encoded = ('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtAL'
                   'Gdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
        expected = ('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9Lgpe'
                    'yGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
        key = hd_wallet.HDKey.decode(encoded)
        child = key.derive_child(0)
        self.assertEqual(
            child.pub().encoded(),
            expected)

    def test_public_m_0_public_derivation_from_pub(self):
        encoded = ('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUa'
                   'pSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB')
        expected = ('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9Lgpe'
                    'yGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
        key = hd_wallet.HDKey.decode(encoded)
        child = key.derive_child(0)
        self.assertEqual(
            child.encoded(),
            expected)

    def test_m_0p_1(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))
               .derive_child(hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1))
        self.assertEqual(key.encoded(),
            'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLn'
            'vSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
        self.assertEquals(key.pub().encoded(),
            'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3'
            'UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')

    def test_m_0p_1_2p(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))
               .derive_child(hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1)
               .derive_child(2 | hd_wallet.PUBLIC_DERIVATION_BIT))
        self.assertEqual(key.encoded(),
            'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBD'
            'ptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
        self.assertEquals(key.pub().encoded(),
            'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VU'
            'NgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')

    def test_m_0p_1_2p_2(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))
               .derive_child(hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1)
               .derive_child(2 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(2))
        self.assertEqual(key.encoded(),
            'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb'
            '2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334')
        self.assertEquals(key.pub().encoded(),
            'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBq'
            'aGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV')

    def test_m_0p_1_2p_2_1000000000(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))
               .derive_child(hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1)
               .derive_child(2 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(2)
               .derive_child(1000000000))
        self.assertEqual(key.encoded(),
            'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8F'
            'Ha8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76')
        self.assertEquals(key.pub().encoded(),
            'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSV'
            'qNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy')

    def test_m_0(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc'
                '9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7'
                'b7875726f6c696663605d5a5754514e4b484542'))
               .derive_child(0))
        self.assertEqual(key.encoded(),
            'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQ'
            'RUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt')
        self.assertEquals(key.pub().encoded(),
            'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9Lgpe'
            'yGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')

    def test_m_0_2147483647p(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc'
                '9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7'
                'b7875726f6c696663605d5a5754514e4b484542'))
               .derive_child(0)
               .derive_child(2147483647 | hd_wallet.PUBLIC_DERIVATION_BIT))
        self.assertEqual(key.encoded(),
            'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vi'
            'dYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9')
        self.assertEquals(key.pub().encoded(),
            'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEy'
            'BLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a')

    def test_m_0_2147483647p_1(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc'
                '9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7'
                'b7875726f6c696663605d5a5754514e4b484542'))
               .derive_child(0)
               .derive_child(2147483647 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1))
        self.assertEqual(key.encoded(),
            'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTR'
            'XSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef')
        self.assertEquals(key.pub().encoded(),
            'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg'
            '5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon')

    def test_m_0_2147483647p_1_2147483646p(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc'
                '9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7'
                'b7875726f6c696663605d5a5754514e4b484542'))
               .derive_child(0)
               .derive_child(2147483647 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1)
               .derive_child(2147483646 | hd_wallet.PUBLIC_DERIVATION_BIT))
        self.assertEqual(key.encoded(),
            'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS'
            '3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc')
        self.assertEquals(key.pub().encoded(),
            'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhg'
            'bmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL')

    def test_m_0_2147483647p_1_2147483646p_2(self):
        key = (hd_wallet.HDPrivKey.generate_master(
            binascii.unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc'
                '9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7'
                'b7875726f6c696663605d5a5754514e4b484542'))
               .derive_child(0)
               .derive_child(2147483647 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(1)
               .derive_child(2147483646 | hd_wallet.PUBLIC_DERIVATION_BIT)
               .derive_child(2))
        self.assertEqual(key.encoded(),
            'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKC'
            'EXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j')
        self.assertEquals(key.pub().encoded(),
            'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdS'
            'nLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt')
