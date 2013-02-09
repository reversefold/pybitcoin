"""."""
import pybitcoin


def test_version():
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
    assert(len(bytes) == 0)
    assert(msg.magic == pmsg.magic)
    assert(msg.command == pmsg.command)
    assert(msg.version == pmsg.version)
    assert(msg.services == pmsg.services)
    assert(msg.timestamp == pmsg.timestamp)
    assert(msg.addr_recv == pmsg.addr_recv)
    assert(msg.addr_from == pmsg.addr_from)
    assert(msg.nonce == pmsg.nonce)
    assert(msg.user_agent == pmsg.user_agent)
    assert(msg.start_height == pmsg.start_height)
    assert(msg.payload == pmsg.payload)
    assert(msg.checksum == pmsg.checksum)
    assert(msg.bytes == pmsg.bytes)
