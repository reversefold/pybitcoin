"""PyBitCoin tests"""
import hashlib
import mox
import os
import struct
import unittest

from pybitcoin import protocol, key


with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tx'), 'r') as f:
    TX_BYTES = f.read().decode('hex')


class TestSplitN(unittest.TestCase):
    def test_splitn(self):
        (a, b) = protocol.splitn('abcde', 2)
        self.assertEqual(len(a), 2)
        self.assertEqual(len(b), 3)
        self.assertEqual(a, 'ab')
        self.assertEqual(b, 'cde')

    def test_splitn_0(self):
        (a, b) = protocol.splitn('12', 0)
        self.assertEqual(a, '')
        self.assertEqual(b, '12')

    def test_splitn_len(self):
        (a, b) = protocol.splitn('12', 2)
        self.assertEqual(a, '12')
        self.assertEqual(b, '')

    def test_splitn_gt_len(self):
        with self.assertRaises(protocol.ParseError):
            (a, b) = protocol.splitn('12', 3)

class TestVarint(mox.MoxTestBase):
    def test_encode_varint_char(self):
        self.assertEquals(protocol.encode_varint(0xfc), '\xfc')

    def test_encode_varint_short(self):
        self.assertEquals(protocol.encode_varint(0xfd), '\xfd\xfd\x00')
        self.assertEquals(protocol.encode_varint(0xfe), '\xfd\xfe\x00')
        self.assertEquals(protocol.encode_varint(0xff), '\xfd\xff\x00')

    def test_encode_varint_int(self):
        self.assertEquals(protocol.encode_varint(0x10000), '\xfe\x00\x00\x01\x00')

    def test_encode_varint_long_long(self):
        self.assertEquals(protocol.encode_varint(0x100000000), '\xff\x00\x00\x00\x00\x01\x00\x00\x00')

    def test_encode_varint_too_long(self):
        with self.assertRaises(protocol.Error):
            protocol.encode_varint(0x10000000000000000)

    def test_parse_varint_char(self):
        self.assertEquals(protocol.parse_varint('\xfc'), (0xfc, ''))

    def test_parse_varint_short(self):
        self.assertEquals(protocol.parse_varint('\xfd\xfd\x00'), (0xfd, ''))
        self.assertEquals(protocol.parse_varint('\xfd\xfe\x00'), (0xfe, ''))
        self.assertEquals(protocol.parse_varint('\xfd\xff\x00'), (0xff, ''))

    def test_parse_varint_int(self):
        self.assertEquals(protocol.parse_varint('\xfe\x00\x00\x01\x00'), (0x10000, ''))

    def test_parse_varint_long_long(self):
        self.assertEquals(protocol.parse_varint('\xff\x00\x00\x00\x00\x01\x00\x00\x00'), (0x100000000, ''))

    def test_parse_varint_too_long(self):
        # since it's impossible to get > 0xff from a single byte, use mox to verify
        self.mox.StubOutWithMock(struct, 'unpack')
        struct.unpack('<B', '\x00').AndReturn((0x100,))
        self.mox.ReplayAll()
        with self.assertRaises(protocol.ParseError):
            protocol.parse_varint('\x00')


class MessageHeaderTest(unittest.TestCase):
    def test_header(self):
        hdr = protocol.MessageHeader('header', 1024, '\x01\x12\xae\x97')
        self.assertEqual(hdr.magic, '\xf9\xbe\xb4\xd9')
        self.assertEqual(hdr.command, 'header')
        self.assertEqual(hdr.payload_length, 1024)
        self.assertEqual(hdr.checksum, '\x01\x12\xae\x97')
        self.assertEqual(hdr.bytes, '\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')

    def test_header_parse(self):
        (hdr, bytes) = protocol.MessageHeader.parse('\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')
        self.assertEqual(bytes, '')
        self.assertEqual(hdr.magic, '\xf9\xbe\xb4\xd9')
        self.assertEqual(hdr.command, 'header')
        self.assertEqual(hdr.payload_length, 1024)
        self.assertEqual(hdr.checksum, '\x01\x12\xae\x97')
        self.assertEqual(hdr.bytes, '\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')


    def test_header_parse_bad_magic(self):
        with self.assertRaises(protocol.ParseError):
            (hdr, bytes) = protocol.MessageHeader.parse('\xe9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')


class MessageTest(unittest.TestCase):
    def test_parse(self):
        pass

    def test_parse_returns_trailing_bytes(self):
        trailing = '\x12\x34'
        (msg, bytes) = protocol.Message.parse(TX_BYTES + trailing)
        self.assertEqual(bytes, trailing)

    def test_parse_fails_with_bad_checksum(self):
        with self.assertRaises(protocol.ParseError):
            parts = protocol.splitn(TX_BYTES, struct.calcsize('<4s12sI'))
            bytes = parts[0] + '\x98' + parts[1][1:]
            (msg, bytes) = protocol.Message.parse(bytes)

    def test_parse_fails_with_extra_bytes(self):
        with self.assertRaises(protocol.ParseError):
            parts = protocol.splitn(TX_BYTES, struct.calcsize('<4s12s'))
            isize = struct.calcsize('<I')
            newsize = struct.unpack('<I', parts[1][:isize])[0] + 1
            (checksum, payload) = protocol.splitn(parts[1][isize:], 4)
            payload += '\x42'
            checksum = protocol.Message.calc_checksum(payload)
            bytes = parts[0] + struct.pack('<I', newsize) + checksum + payload
            (msg, bytes) = protocol.Message.parse(bytes)

    def test_unknown_command(self):
        msg = protocol.Message('unknown')
        msg.payload = ''
        with self.assertRaises(protocol.ParseError):
            protocol.Message.parse(msg.bytes)


class VersionTest(unittest.TestCase):
    def test_version(self):
        msg = protocol.Version(60002, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), 7284544412836900411, '/Satoshi:0.7.2/', 212672, 1, 1355854353)
        (pmsg, bytes) = protocol.Message.parse(msg.bytes)
        for f in msg.__dict__:
            try:
                print '%s: %r' % (f, msg.__dict__[f])
            except:
                print '%s: <>' % (f,)
            try:
                print '%s: %r' % (f, pmsg.__dict__[f])
            except:
                print '%s: <>' % (f,)
        self.assertEqual(len(bytes), 0)
        self.assertEqual(msg.header.magic, pmsg.header.magic)
        self.assertEqual(msg.header.command, pmsg.header.command)
        self.assertEqual(msg.version, pmsg.version)
        self.assertEqual(msg.services, pmsg.services)
        self.assertEqual(msg.timestamp, pmsg.timestamp)
        self.assertEqual(msg.addr_recv, pmsg.addr_recv)
        self.assertEqual(msg.addr_from, pmsg.addr_from)
        self.assertEqual(msg.nonce, pmsg.nonce)
        self.assertEqual(msg.user_agent, pmsg.user_agent)
        self.assertEqual(msg.start_height, pmsg.start_height)
        self.assertEqual(msg.payload, pmsg.payload)
        self.assertEqual(msg.header.checksum, pmsg.header.checksum)
        self.assertEqual(msg.checksum, pmsg.checksum)
        self.assertEqual(msg.bytes, pmsg.bytes)


class TxInTest(unittest.TestCase):
    def test_txin(self):
        tx_hash = hashlib.sha256(hashlib.sha256('enigmaenigmaenigma').digest()).digest()
        script = 'scriptscriptscript'
        idx = 75
        seq = 42
        txin1 = txin = protocol.TxIn((tx_hash, idx), script, seq)
        self.assertEquals(txin.previous_output, (tx_hash, idx))
        self.assertEquals(txin.signature_script, script)
        self.assertEquals(txin.sequence, seq)

        (txin, bytes) = protocol.TxIn.parse(txin.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(txin.previous_output, (tx_hash, idx))
        self.assertEquals(txin.signature_script, script)
        self.assertEquals(txin.sequence, seq)

        self.assertEquals(txin1, txin)


class PubKeyScriptTest(unittest.TestCase):
    def test_pks(self):
        script = '\x42' * 5
        pks = protocol.PubKeyScript(script)
        self.assertEquals(pks.bytes, script)
        self.assertEquals(repr(pks), script.encode('hex'))
        self.assertFalse(pks.is_standard_transaction)

        addr = '\x42' * 20
        script = '\x76\xa9\x14' + addr + '\x88\xac'
        pks = protocol.PubKeyScript(script)
        self.assertEquals(pks.bytes, script)
        self.assertEquals(
            repr(pks),
            'To Addr: ' + key.base58_encode(key.address_from_pk_hash(addr)))
        self.assertTrue(pks.is_standard_transaction)

        self.assertEquals(pks, pks)


class TxOutTest(unittest.TestCase):
    def test_txout(self):
        val = 12345
        pksbytes = '\x32' * 40
        pks = protocol.PubKeyScript(pksbytes)
        txout1 = txout = protocol.TxOut(val, pks)
        self.assertEquals(txout.value, val)
        self.assertEquals(txout.pk_script.bytes, pksbytes)

        (txout, bytes) = protocol.TxOut.parse(txout.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(txout.value, val)
        self.assertEquals(txout.pk_script.bytes, pksbytes)

        self.assertEquals(txout1, txout)


class TransactionTest(unittest.TestCase):
    def test_parse(self):
        (tx, bytes) = protocol.TransactionMessage.parse(TX_BYTES)
        self.assertEqual(bytes, '')

    def test_transaction(self):
        v = 42
        tx_hash = hashlib.sha256(hashlib.sha256('enigmaenigmaenigma').digest()).digest()
        script = 'scriptscriptscript'
        idx = 75
        seq = 42
        txin = protocol.TxIn((tx_hash, idx), script, seq)
        txin = [txin]
        val = 12345
        pksbytes = '\x32' * 40
        pks = protocol.PubKeyScript(pksbytes)
        txout = protocol.TxOut(val, pks)
        txout = [txout]
        lock = 12345678

        tx1 = tx = protocol.TransactionMessage(protocol.Transaction(v, txin, txout, lock))
        self.assertEquals(tx.tx.version, v)
        self.assertEquals(tx.tx.tx_in, txin)
        self.assertEquals(tx.tx.tx_out, txout)
        self.assertEquals(tx.tx.lock_time, lock)

        (tx, bytes) = protocol.TransactionMessage.parse(tx.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(tx.tx.version, v)
        self.assertEquals(tx.tx.tx_in, txin)
        self.assertEquals(tx.tx.tx_out, txout)
        self.assertEquals(tx.tx.lock_time, lock)

        self.assertEquals(tx1, tx)


class VerackTest(unittest.TestCase):
    def test_verack(self):
        msg = protocol.Verack()
        (parsed, bytes) = protocol.Verack.parse(msg.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(parsed.bytes, msg.bytes)


class PingTest(unittest.TestCase):
    def test_verack(self):
        msg = protocol.Ping()
        (parsed, bytes) = protocol.Ping.parse(msg.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(parsed.bytes, msg.bytes)
