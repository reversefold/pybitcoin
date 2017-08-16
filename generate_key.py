#!/usr/bin/env python

from __future__ import print_function
from pybitcoin import key
from pybitcoin import byte_util


def main():
    priv = key.generate_priv()
    priv_enc = key.encode_privkey(priv)
    priv_cmp_enc = key.encode_privkey_compressed(priv)
    pub = key.priv_to_pub(priv)
    addr = byte_util.base58_encode(key.pub_to_address(pub))
    addr_comp = byte_util.base58_encode(key.pub_to_address_compressed(pub))
    print('Address: %s\nPrivate Key Encoded: %s\nAddress (compressed): %s\nPrivate Key Encoded (compressed): %s' % (addr, priv_enc, addr_comp, priv_cmp_enc))


if __name__ == '__main__':
    main()
