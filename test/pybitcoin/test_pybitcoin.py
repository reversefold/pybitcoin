"""."""
import unittest

import pybitcoin


class MessageHeaderTest(unittest.TestCase):
    def test_header(self):
        hdr = pybitcoin.MessageHeader('header', 1024, '\x01\x12\xae\x97')
        self.assertEqual(hdr.magic, '\xf9\xbe\xb4\xd9')
        self.assertEqual(hdr.command, 'header')
        self.assertEqual(hdr.payload_length, 1024)
        self.assertEqual(hdr.checksum, '\x01\x12\xae\x97')
        self.assertEqual(hdr.bytes, '\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')

    def test_header_parse(self):
        (hdr, bytes) = pybitcoin.MessageHeader.parse('\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')
        self.assertEqual(bytes, '')
        self.assertEqual(hdr.magic, '\xf9\xbe\xb4\xd9')
        self.assertEqual(hdr.command, 'header')
        self.assertEqual(hdr.payload_length, 1024)
        self.assertEqual(hdr.checksum, '\x01\x12\xae\x97')
        self.assertEqual(hdr.bytes, '\xf9\xbe\xb4\xd9header\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x12\xae\x97')


class VersionTest(unittest.TestCase):
    def test_version(self):
        msg = pybitcoin.Version(60002, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), 7284544412836900411, '/Satoshi:0.7.2/', 212672, 1, 1355854353)
        (pmsg, bytes) = pybitcoin.Message.parse(msg.bytes)
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
