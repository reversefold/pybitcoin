#!/usr/bin/env python

import binascii
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
import multiprocessing
from pprint import pprint, pformat
import re
import requests
import sys
import traceback

from pybitcoin import key, byte_util

GETWORK_URL = 'https://vanitypool.appspot.com/getWork'
SOLVE_URL = 'https://vanitypool.appspot.com/solve'

VANITY_RE = r'(firstname|lastname|firstlast)'
PAYOUT_ADDRESS = '1BTCrcKNC7FoJsAzS3XPubz6vHwZCp5sx9'

VANITY_RE = re.compile(VANITY_RE, re.IGNORECASE)


INC = 10


def mine(g_num, work):
    num = 0
    while True:
        try:
            priv = key.generate_priv()
            pub = key.priv_to_pub(priv)
            addr = byte_util.base58_encode(key.pub_to_address(pub))
            addr_comp = byte_util.base58_encode(key.pub_to_address_compressed(pub))
            num += 1
            if num % INC == 0:
                with g_num.get_lock():
                    g_num.value += INC
                # if g_num.value > 10000:
                #     return
            if any(VANITY_RE.match(a) for a in [addr, addr_comp]):
                try:
                    priv_enc = key.encode_privkey(priv)
                except Exception, e:
                    priv_enc = repr(e)
                try:
                    priv_cmp_enc = key.encode_privkey_compressed(priv)
                except Exception, e:
                    priv_cmp_enc = repr(e)
                msg = '\nI found one!\nAddress: %s\nAddress (compressed): %s\nPrivate Key (raw): %r\nPrivate Key Encoded: %s\nPrivate Key Encoded (compressed): %s\n' % (addr, addr_comp, priv, priv_enc, priv_cmp_enc)
                print msg[:-1]
                with open('found_keys', 'a') as found_keys:
                    found_keys.write(msg)

            for rec in work:
                pub_sum = pub + rec['public_key']
                addr = byte_util.base58_encode(key.pub_to_address(pub_sum))
                addr_comp = byte_util.base58_encode(key.pub_to_address_compressed(pub_sum))
                if not any(a.startswith(rec['pattern']) for a in [addr, addr_comp]):
                    continue

                try:
                    priv_hex = hex(priv)[2:].rstrip('L').upper()
                except Exception, e:
                    priv_hex = repr(e)
                try:
                    priv_enc = key.encode_privkey(priv)
                except Exception, e:
                    priv_enc = repr(e)
                try:
                    priv_cmp_enc = key.encode_privkey_compressed(priv)
                except Exception, e:
                    priv_cmp_enc = repr(e)
                msg = StringIO()
                msg.write('\nI solved one!\n%s\nAddress: %s\nAddress (compressed): %s\nPrivate Key (hex): %s\nPrivate Key (raw): %r\nPrivate Key Encoded: %s\nPrivate Key Encoded (compressed): %s\n' % (pformat(rec), addr, addr_comp, priv_hex, priv, priv_enc, priv_cmp_enc))

                resp = requests.post(SOLVE_URL, {'key': '%s:%s' % (rec['pattern'], rec['public_key_hex']), 'privateKey': priv_hex, 'bitcoinAddress': PAYOUT_ADDRESS})
                msg.write(repr(resp))
                msg.write('\n')
                msg.write(resp.text)
                msg.write('\n')
                if resp.text != 'OK!':
                    msg.write('Solution post failed!!!')
                    msg.write('\n')
                msg = msg.getvalue()
                print msg[:-1]
                with open('solved_keys', 'a') as solved_keys:
                    solved_keys.write(msg)

        except Exception, e:
            traceback.print_exc()


def getwork():
    url = GETWORK_URL
    data = requests.get(url).text

    headers = ['pattern', 'public_key_hex', 'network_byte', 'reward', 'comment']
    work = []
    for line in data.split('\n'):
        if ';' not in line:
            continue
        fields = line.split(';')
        if ':' not in fields[0]:
            continue
        fields = fields[0].split(':') + fields[-1:]
        if len(fields) != len(headers):
            print 'fields do not match headers: %r' % (fields,)
        rec = dict(zip(headers, fields))
        if rec['pattern'][0] != '1':
            print 'pattern does not start with 1: %s' % (rec['pattern'],)
            continue
        rec['reward'] = float(rec['reward'])
        rec['work_to_reward'] = pow(58, len(rec['pattern']) - 1) / rec['reward']
        rec['public_key_enc'] = binascii.unhexlify(rec['public_key_hex'])
        rec['public_key'] = key.decode_pub(rec['public_key_enc'])
        work.append(rec)
    return work


NUM_PER_DOT = 100
NUM_PER_LINE = 5000


def main():
    work = getwork()
    work.sort(key=lambda r: r['work_to_reward'])
    work = work[:10]
    pprint(work)
    num = multiprocessing.Value('L')
    procs = []
    for _ in xrange(multiprocessing.cpu_count() - 2):
        proc = multiprocessing.Process(target=mine, args=(num, work))
        proc.start()
        procs.append(proc)

    l_num = 0
    lt_num = 0
    while procs:
        for proc in procs:
            proc.join(0.001)
            if not proc.is_alive():
                procs.remove(proc)
        nval = num.value
        num_dots = (nval - l_num) // NUM_PER_DOT
        writestr = ''
        for _ in xrange(num_dots):
            writestr += '.'
            if nval - lt_num > NUM_PER_LINE:
                lt_num = nval // NUM_PER_LINE * NUM_PER_LINE
                writestr += ' %u\n' % (lt_num,)
            l_num = nval // NUM_PER_DOT * NUM_PER_DOT
        if writestr:
            sys.stdout.write(writestr)
            sys.stdout.flush()
        # if nval > 10000:
        #     sys.exit()


if __name__ == '__main__':
    main()
