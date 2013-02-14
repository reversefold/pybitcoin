from hashlib import sha256
import logging
import struct
import time


log = logging.getLogger(__name__)


MAGIC = struct.pack('<I', 0xD9B4BEF9)


class Error(Exception):
    pass


class ParseError(Error):
    pass


def fmt_w_size(fmt):
    return (fmt, struct.calcsize(fmt))


def splitn(bytes, n):
    return bytes[:n], bytes[n:]


def parse(bytes, fmt):
    (bit, bytes) = splitn(bytes, fmt[1])
    return (struct.unpack(fmt[0], bit), bytes)


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
        return (b0, bytes[1:])
    elif b0 == 0xfd:
        return (struct.unpack('<H', bytes[1:3])[0], bytes[3:])
    elif b0 == 0xfe:
        return (struct.unpack('<I', bytes[1:5])[0], bytes[5:])
    elif b0 == 0xff:
        return (struct.unpack('<Q', bytes[1:9])[0], bytes[9:])
    else:
        raise ParseError('Inconceivable! %r' % (b0,))


def encode_varstr(s):
    return encode_varint(len(s)) + s


def parse_varstr(bytes):
    (str_len, bytes) = parse_varint(bytes)
    return splitn(bytes, str_len)


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
    ((services,), bytes) = parse(bytes, ADDR_SVCS_FMT)
    ((_, _, _, ipbytes, port), bytes) = parse(bytes, ADDR_BARE_FMT)
    ip = '.'.join(str(ord(o)) for o in ipbytes)
    return ((services, ip, port), bytes)


ADDR_FMT = fmt_w_size('<I')
def encode_addr(addr, ts):
    return struct.pack(ADDR_FMT[0], ts) + encode_addr_bare(addr)


def parse_addr(bytes):
    (ts, bytes) = parse(bytes, ADDR_FMT)
    (addr, bytes) = parse_addr_bare(bytes)
    return (ts, addr, bytes)


class MessageHeader(object):
    HEADER_FMT = fmt_w_size('<4s12sI4s')

    def __init__(self, command=None, payload_length=None, checksum=None):
        self.magic = MAGIC
        self.command = command
        self.payload_length = payload_length
        self.checksum = checksum

    @property
    def bytes(self):
        return struct.pack(self.HEADER_FMT[0],
                           self.magic, self.command, self.payload_length, self.checksum)

    @classmethod
    def parse(cls, bytes):
        ((magic, command, payload_length, checksum), bytes) = parse(bytes, cls.HEADER_FMT)
        if magic != MAGIC:
            raise ParseError('Magic does not match: %r' % (magic,))
        command = command.rstrip('\x00')
        return (cls(command, payload_length, checksum), bytes)


class Message(object):
    def __init__(self, command=None, header=None):
        if header is None:
            self.header = MessageHeader(command)
        else:
            self.header = header

    @classmethod
    def calc_checksum(cls, payload):
        return sha256(sha256(payload).digest()).digest()[:4]

    @property
    def checksum(self):
        return self.calc_checksum(self.payload)

    @property
    def bytes(self):
        if self.header is None:
            self.header = MessageHeader(self.command, len(self.payload), self.checksum)
        else:
            self.header.payload_length = len(self.payload)
            self.header.checksum = self.checksum
        return self.header.bytes + self.payload

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        (payload, bytes) = splitn(bytes, header.payload_length)
        if header.checksum != cls.calc_checksum(payload):
            raise ParseError('Checksum is incorrect')
        if header.command not in COMMAND_CLASS_MAP:
            raise ParseError('Unknown command %s' % (header.command,))
        return COMMAND_CLASS_MAP[header.command].parse(payload, header)


class Version(Message):
    BITS = [fmt_w_size(f) for f in ['<iQq', '<Q', '<i']]

    def __init__(self, version, addr_recv, addr_from, nonce, user_agent, start_height, services=0x01, timestamp=None, header=None):
        super(Version, self).__init__('version', header=header)
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
    def parse(cls, bytes, header=None):
        ((version, services, timestamp), bytes) = parse(bytes, cls.BITS[0])
        (addr_recv, bytes) = parse_addr_bare(bytes)
        (addr_from, bytes) = parse_addr_bare(bytes)
        ((nonce,), bytes) = parse(bytes, cls.BITS[1])
        (user_agent, bytes) = parse_varstr(bytes)
        ((start_height,), bytes) = parse(bytes, cls.BITS[2])
        return (cls(version,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent,
                    start_height,
                    services,
                    timestamp,
                    header),
                bytes)


class Verack(Message):
    def __init__(self, header=None):
        super(Verack, self).__init__('verack', header=header)

    @property
    def payload(self):
        return ''

    @classmethod
    def parse(cls, bytes, header=None):
        return (cls(header), bytes)


class Ping(Message):
    def __init__(self, header=None):
        super(Verack, self).__init__('ping', header=header)

    @property
    def payload(self):
        return ''

    @classmethod
    def parse(cls, bytes, header=None):
        return (cls(header), bytes)


class Address(Message):
    def __init__(self, header=None):
        super(Address, self).__init__('addr', header=header)

    @property
    def payload(self):
        raise Error()

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error()


class Inventory(Message):
    FORMAT = fmt_w_size('<I32s')

    def __init__(self, hashes=None, header=None):
        super(Inventory, self).__init__('inv', header=header)
        self.hashes = hashes if hashes is not None else []

    @property
    def payload(self):
        return ''.join([
            encode_varint(len(self.hashes))]
            + [
                struct.pack(self.FORMAT, *item)
                for item in self.hashes
            ])

    @classmethod
    def parse(cls, bytes, header=None):
        (count, bytes) = parse_varint(bytes)
        hashes = []
        for _ in xrange(count):
            (item, bytes) = parse(bytes, cls.FORMAT)
            hashes.append(item)
        return (cls(hashes, header), bytes)

    def __repr__(self):
        return 'inv([' + ', '.join(repr(i) for i in self.hashes) + '])'


COMMAND_CLASS_MAP = {
    'version': Version,
    'verack': Verack,
    'ping': Ping,
    'inv': Inventory,
}
