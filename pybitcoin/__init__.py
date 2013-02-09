"""PyBitCoin"""
from hashlib import sha256
import struct
import time


MAGIC = struct.pack('<I', 0xD9B4BEF9)


class Error(Exception):
    pass


class ParseError(Error):
    pass


def visual(bytes):
    return ' '.join(c.encode('hex') for c in bytes).upper()


def visual2(msg):
    ii = [4, 12, 4, 4,
          4, 8, 8, 26, 26, 8, 16, 4]
    bytes = msg.bytes
    return '\n'.join(
        visual(b)
        for b in (
                bytes[sum(ii[:i]):sum(ii[:i]) + ii[i]]
                for i in xrange(len(ii))
        )
    ).upper()


def fmt_w_size(fmt):
    return (fmt, struct.calcsize(fmt))


def splitn(bytes, n):
    return bytes[:n], bytes[n:]


def parse(bytes, fmt):
    (bit, bytes) = splitn(bytes, fmt[1])
    return (bytes, struct.unpack(fmt[0], bit))


def encode_varint(i):
    if i < 0xfd:
        return struct.pack('<B', i)
    elif i <= 0xffff:
        return struct.pack('<BH', 0xfd, i)
    elif i <= 0xffffffff:
        return struct.pack('<BI', 0xfe, i)
    elif i <= 0xffffffffffffffff:
        return struct.pack('<BQ', 0xff, i)
    else:
        raise Error('int too big for varint: %r' % (i,))


def parse_varint(bytes):
    (b0,) = struct.unpack('<B', bytes[0])
    if b0 < 0xfd:
        return (bytes[1:], b0)
    elif b0 == 0xfd:
        return (bytes[3:], struct.unpack('<H', bytes[1:3])[0])
    elif b0 == 0xfe:
        return (bytes[5:], struct.unpack('<I', bytes[1:5])[0])
    elif b0 == 0xff:
        return (bytes[9:], struct.unpack('<Q', bytes[1:9])[0])
    else:
        raise ParseError('Inconceivable! %r' % (b0,))


def encode_varstr(s):
    return encode_varint(len(s)) + s


def parse_varstr(bytes):
    (bytes, str_len) = parse_varint(bytes)
    return splitn(bytes, str_len)[::-1]


ADDR_SVCS_FMT = fmt_w_size('<Q')
ADDR_BARE_FMT = fmt_w_size('!10sBB4sH')
def encode_addr_bare(addr):
    (services, ip, port) = addr
    return (struct.pack(ADDR_SVCS_FMT[0], services)
            + struct.pack(
                ADDR_BARE_FMT[0],
                '', 0xff, 0xff,
                ''.join(chr(int(o)) for o in ip.split('.')),
                port))


def parse_addr_bare(bytes):
    (bytes, (services,)) = parse(bytes, ADDR_SVCS_FMT)
    (bytes, (_, _, _, ipbytes, port)) = parse(bytes, ADDR_BARE_FMT)
    ip = '.'.join(str(ord(o)) for o in ipbytes)
    return (bytes, (services, ip, port))


ADDR_FMT = fmt_w_size('<I')
def encode_addr(addr, ts):
    return struct.pack(ADDR_FMT[0], ts) + encode_addr_bare(addr)


def parse_addr(bytes):
    (bytes, ts) = parse(bytes, ADDR_FMT)
    (bytes, addr) = parse_addr_bare(bytes)
    return (bytes, ts, addr)


class Message(object):
    HEADER_FMT = fmt_w_size('<4s12sI4s')

    def __init__(self, command):
        self.magic = MAGIC
        self.command = command

    @property
    def checksum(self):
        return self.calc_checksum(self.payload)

    @classmethod
    def calc_checksum(cls, payload):
        return sha256(sha256(payload).digest()).digest()[:4]

    @property
    def bytes(self):
        return (struct.pack(self.HEADER_FMT[0], self.magic, self.command, len(self.payload), self.checksum) +
                self.payload)

    @classmethod
    def parse(cls, bytes):
        (bytes, (magic, command, payload_len, checksum)) = parse(bytes, cls.HEADER_FMT)
        if magic != MAGIC:
            raise ParseError('Magic does not match: %r' % (magic,))
        (payload, bytes) = splitn(bytes, payload_len)
        if checksum != cls.calc_checksum(payload):
            raise ParseError('Checksum is incorrect')
        command = command.rstrip('\x00')
        return COMMAND_MAP[command].parse(payload)


#EX_VERSION = Message('version', '62 EA 00 00 01 00 00 00 00 00 00 00 11 B2 D0 50 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 3B 2E B3 5D 8C E6 17 65 0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F C0 3E 03 00'.replace(' ', '').decode('hex'))
#EX_VERACK = Message('verack', '\x01\xe2\x15\x10\x4d\x01' + ('\x00' * 17) + '\xff\xff\x0a\x00\x00\x01\x20\x8d')


class Version(Message):
    BITS = [(f, struct.calcsize(f)) for f in ['<iQq', '<Q', '<i']]

    def __init__(self, version, addr_recv, addr_from, nonce, user_agent, start_height, services=0x01, timestamp=None):
        super(Version, self).__init__('version')
        self.version = version
        self.services = services
        self.timestamp = timestamp if timestamp is not None else long(time.time())
        self.addr_recv = addr_recv
        self.addr_from = addr_from
        self.nonce = nonce
        self.user_agent = user_agent
        self.start_height = start_height

    @property
    def payload(self):
        return ''.join([
            struct.pack(self.BITS[0][0], self.version, self.services, self.timestamp),
            encode_addr_bare(self.addr_recv),
            encode_addr_bare(self.addr_from),
            struct.pack(self.BITS[1][0], self.nonce),
            encode_varstr(self.user_agent),
            struct.pack(self.BITS[2][0], self.start_height)])

    @classmethod
    def parse(cls, bytes):
        (bytes, (version, services, timestamp)) = parse(bytes, cls.BITS[0])
        (bytes, addr_recv) = parse_addr_bare(bytes)
        (bytes, addr_from) = parse_addr_bare(bytes)
        (bytes, (nonce,)) = parse(bytes, cls.BITS[1])
        (bytes, user_agent) = parse_varstr(bytes)
        (bytes, (start_height,)) = parse(bytes, cls.BITS[2])
        return (bytes,
                Version(version,
                        addr_recv,
                        addr_from,
                        nonce,
                        user_agent,
                        start_height,
                        services,
                        timestamp))


class Verack(Message):
    def __init__(self):
        super(Verack, self).__init__('verack')

    @property
    def payload(self):
        return ''

    @classmethod
    def parse(cls, bytes):
        if len(bytes) == 0:
            raise ParseError('Verack should be empty')
        return Verack()


class Ping(Message):
    def __init__(self):
        super(Verack, self).__init__('ping')

    @property
    def payload(self):
        return ''

    @classmethod
    def parse(cls, bytes):
        if len(bytes) == 0:
            raise ParseError('Ping should be empty')
        return Ping()


COMMAND_MAP = {
    'version': Version,
    'verack': Verack,
    'ping': Ping,
}
