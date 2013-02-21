"""PyBitCoin tests"""
import hashlib
import os
import unittest

from pybitcoin import protocol


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
        txin = protocol.TxIn((tx_hash, idx), script, seq)
        self.assertEquals(txin.previous_output, (tx_hash, idx))
        self.assertEquals(txin.signature_script, script)
        self.assertEquals(txin.sequence, seq)

        (txin, bytes) = protocol.TxIn.parse(txin.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(txin.previous_output, (tx_hash, idx))
        self.assertEquals(txin.signature_script, script)
        self.assertEquals(txin.sequence, seq)


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
            'To Addr: ' + protocol.base58_encode(protocol.address_from_pk_hash(addr)))
        self.assertTrue(pks.is_standard_transaction)


class TxOutTest(unittest.TestCase):
    def test_txout(self):
        val = 12345
        pksbytes = '\x32' * 40
        pks = protocol.PubKeyScript(pksbytes)
        txout = protocol.TxOut(val, pks)
        self.assertEquals(txout.value, val)
        self.assertEquals(txout.pk_script.bytes, pksbytes)

        (txout, bytes) = protocol.TxOut.parse(txout.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(txout.value, val)
        self.assertEquals(txout.pk_script.bytes, pksbytes)


class TransactionTest(unittest.TestCase):
    def test_parse(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tx'), 'r') as f:
            (tx, bytes) = protocol.Transaction.parse(f.read().decode('hex'))
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

        tx = protocol.Transaction(v, txin, txout, lock)
        self.assertEquals(tx.version, v)
#        self.assertEquals(tx.tx_in, txin)
#        self.assertEquals(tx.tx_out, txout)
        self.assertEquals(tx.lock_time, lock)

        (tx, bytes) = protocol.Transaction.parse(tx.bytes)
        self.assertEquals(bytes, '')
        self.assertEquals(tx.version, v)
#        self.assertEquals(tx.tx_in, txin)
#        self.assertEquals(tx.tx_out, txout)
        self.assertEquals(tx.lock_time, lock)
