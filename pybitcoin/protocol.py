import binascii
from hashlib import sha256
import logging
import random
import struct
import time

from pybitcoin import util, key, byte_util
from pybitcoin.byte_util import Error, ParseError, fmt_w_size, splitn, parse


log = logging.getLogger(__name__)


PROTOCOL_VERSION = 70011

MAGIC = struct.pack('<I', 0xD9B4BEF9)

UINT32_FMT = fmt_w_size('<I')
INT64_FMT = fmt_w_size('<q')


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
def encode_addr(ts, addr):
    return struct.pack(ADDR_FMT[0], ts) + encode_addr_bare(addr)


def parse_addr(bytes):
    ((ts,), bytes) = parse(bytes, ADDR_FMT)
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

    def __repr__(self):
        return 'MessageHeader(%s, %s, %r, %s)' % (
            util.visual(self.magic),
            self.command,
            self.payload_length,
            util.visual(self.checksum))


class Message(object):
    def __init__(self, header=None):
        if header is None:
            self._header = MessageHeader(self.COMMAND)  # self.__class__.COMMAND
        else:
            self._header = header

    @classmethod
    def calc_checksum(cls, payload):
        return sha256(sha256(payload).digest()).digest()[:4]

    @property
    def checksum(self):
        return self.calc_checksum(self.payload)

    @property
    def bytes(self):
        return self.header.bytes + self.payload

    @property
    def header(self):
        self._header.payload_length = len(self.payload)
        self._header.checksum = self.checksum
        return self._header

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        log.debug('Parsing message %s' % (header.command,))
        (payload, bytes) = splitn(bytes, header.payload_length)
        if header.checksum != cls.calc_checksum(payload):
            raise ParseError('Checksum is incorrect')
        if header.command not in COMMAND_CLASS_MAP:
            raise ParseError('Unknown command %s' % (header.command,))
        (msg, empty) = COMMAND_CLASS_MAP[header.command].parse(payload, header)
        if empty != '':
            raise ParseError('Trailing bytes after parsing payload for command %s' % (header.command,))
        return (msg, bytes)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.header)


class Version(Message):
    COMMAND = 'version'
    BITS = [fmt_w_size(f) for f in ['<iQq', '<Q', '<i?']]

    def __init__(self, version, addr_recv, addr_from, nonce, user_agent, start_height, relay, services=0x01, timestamp=None, header=None):
        super(Version, self).__init__(header=header)
        self.version = version
        self.services = services
        self.timestamp = timestamp if timestamp is not None else long(time.time())
        self.addr_recv = addr_recv
        self.addr_from = addr_from
        self.nonce = nonce
        self.user_agent = user_agent
        self.start_height = start_height
        self.relay = relay

    @property
    def payload(self):
        return ''.join([
            struct.pack(self.BITS[0][0], self.version, self.services, self.timestamp),
            encode_addr_bare(self.addr_recv),
            encode_addr_bare(self.addr_from),
            struct.pack(self.BITS[1][0], self.nonce),
            encode_varstr(self.user_agent),
            struct.pack(self.BITS[2][0], self.start_height, self.relay)])

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        ((version, services, timestamp), bytes) = parse(bytes, cls.BITS[0])
        (addr_recv, bytes) = parse_addr_bare(bytes)
        (addr_from, bytes) = parse_addr_bare(bytes)
        ((nonce,), bytes) = parse(bytes, cls.BITS[1])
        (user_agent, bytes) = parse_varstr(bytes)
        ((start_height, relay), bytes) = parse(bytes, cls.BITS[2])
        return (cls(version,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent,
                    start_height,
                    relay,
                    services,
                    timestamp,
                    header),
                bytes)

    def __repr__(self):
        return 'Version(%r, %r, %r, %r, %r, %r, %r, %r, %r, %r)' % (
            self.header,
            self.version,
            self.services,
            self.timestamp,
            self.addr_recv,
            self.addr_from,
            self.nonce,
            self.user_agent,
            self.start_height,
            self.relay)


class Verack(Message):
    COMMAND = 'verack'

    def __init__(self, header=None):
        super(Verack, self).__init__(header=header)

    @property
    def payload(self):
        return ''

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        return (cls(header), bytes)


class PingPong(Message):
    PAYLOAD = fmt_w_size('<Q')

    def __init__(self, nonce=None, header=None):
        super(PingPong, self).__init__(header=header)
        if nonce is None:
            nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
        self.nonce = nonce

    @property
    def payload(self):
        return struct.pack(self.PAYLOAD[0], self.nonce)

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        ((nonce,), bytes) = parse(bytes, cls.PAYLOAD)
        return (cls(nonce, header), bytes)

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.header,
            self.nonce)


class Ping(PingPong):
    COMMAND = 'ping'


class Pong(PingPong):
    COMMAND = 'pong'


class AddressList(Message):
    COMMAND = 'addr'

    def __init__(self, addresses=None, header=None):
        super(AddressList, self).__init__(header=header)
        self.addresses = addresses if addresses is not None else []

    @property
    def payload(self):
        return (encode_varint(len(self.addresses))
                + ''.join(encode_addr(*a) for a in self.addresses))

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        (addr_count, bytes) = parse_varint(bytes)
        addresses = []
        for _ in xrange(addr_count):
            (ts, addr, bytes) = parse_addr(bytes)
            addresses.append((ts, addr))
        return (cls(addresses, header), bytes)

    def __repr__(self):
        return 'AddressList(%r, [%s])' % (
            self.header, ', '.join(repr(a) for a in self.addresses))

    def __eq__(self, b):
        return self.addresses == b.addresses


class InventoryVector(Message):
    HASH_FMT = fmt_w_size('<I32s')
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    HASH_TYPES = {
        0: 'ERROR',
        1: 'MSG_TX',
        2: 'MSG_BLOCK'}

    def __init__(self, hashes=None, header=None):
        super(InventoryVector, self).__init__(header=header)
        self.hashes = hashes if hashes is not None else []

    @property
    def payload(self):
        return ''.join([
            encode_varint(len(self.hashes))]
            + [
                struct.pack(self.HASH_FMT[0], *item)
                for item in self.hashes
            ])

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        (count, bytes) = parse_varint(bytes)
        hashes = []
        for _ in xrange(count):
            (item, bytes) = parse(bytes, cls.HASH_FMT)
            hashes.append(item)
        return (cls(hashes, header), bytes)

    def __repr__(self):
        return 'Inventory([%s])' % (
            ', '.join(
                '(%s, %s)' % (
                    self.HASH_TYPES.get(i[0], '<UNKNOWN>'),
                    binascii.hexlify(i[1]))
                for i in self.hashes),)


class Inventory(InventoryVector):
    COMMAND = 'inv'

    def __init__(self, hashes=None, header=None):
        super(Inventory, self).__init__(hashes=hashes, header=header)


class GetData(InventoryVector):
    COMMAND = 'getdata'

    def __init__(self, hashes=None, header=None):
        super(GetData, self).__init__(hashes=hashes, header=header)


class TxIn(object):
    OUTPOINT_FMT = fmt_w_size('<32sI')

    def __init__(self, previous_output, signature_script, sequence):
        self.previous_output = previous_output
        self.signature_script = signature_script
        self.sequence = sequence

    @classmethod
    def parse(cls, bytes):
        (previous_output, bytes) = parse(bytes, cls.OUTPOINT_FMT)
        (script_len, bytes) = parse_varint(bytes)
        (signature_script, bytes) = splitn(bytes, script_len)
        ((sequence,), bytes) = parse(bytes, UINT32_FMT)
        return (cls(previous_output, signature_script, sequence), bytes)

    @property
    def bytes(self):
        return ''.join([
            struct.pack(self.OUTPOINT_FMT[0], *self.previous_output),
            encode_varint(len(self.signature_script)),
            self.signature_script,
            struct.pack(UINT32_FMT[0], self.sequence)])

    def __eq__(self, b):
        return (self.previous_output == b.previous_output
                and self.signature_script == b.signature_script
                and self.sequence == b.sequence)

    def __repr__(self):
        return 'TxIn((%s, %r), %s, %r)' % (
            binascii.hexlify(self.previous_output[0]), self.previous_output[1],
            binascii.hexlify(self.signature_script),
            self.sequence)


class PubKeyScript(object):
    def __init__(self, bytes):
        self.bytes = bytes

    @property
    def is_standard_transaction(self):
        return (self.bytes.startswith('\x76\xa9\x14')
                and self.bytes.endswith('\x88\xac')
                and len(self.bytes) == 25)

    @property
    def to_address(self):
        if self.is_standard_transaction:
            return byte_util.base58_encode(
                key.address_from_pk_hash(self.bytes[3:-2]))
        else:
            return None

    def __eq__(self, b):
        return self.bytes == b.bytes

    def __len__(self):
        return len(self.bytes)

    def __repr__(self):
        if self.is_standard_transaction:
            return 'To Addr: %s' % (self.to_address,)
        return binascii.hexlify(self.bytes)


class TxOut(object):
    def __init__(self, value, pk_script):
        self.value = value
        self.pk_script = pk_script

    @classmethod
    def parse(cls, bytes):
        ((value,), bytes) = parse(bytes, INT64_FMT)
        (script_len, bytes) = parse_varint(bytes)
        (pk_script, bytes) = splitn(bytes, script_len)
        return (cls(value, PubKeyScript(pk_script)), bytes)

    @property
    def bytes(self):
        return ''.join([
            struct.pack(INT64_FMT[0], self.value),
            encode_varint(len(self.pk_script)),
            self.pk_script.bytes])

    def __eq__(self, b):
        return self.value == b.value and self.pk_script == b.pk_script

    def __repr__(self):
        return 'TxOut(%r, %r)' % (self.value, self.pk_script)


class Transaction(object):
    def __init__(self, version, tx_in, tx_out, lock_time):
        self.version = version
        self.tx_in = tx_in
        self.tx_out = tx_out
        self.lock_time = lock_time

    @property
    def tx_hash(self):
        return sha256(sha256(self.bytes).digest()).digest()

    @classmethod
    def parse(cls, bytes):
        ((version,), bytes) = parse(bytes, UINT32_FMT)
        (num_tx_in, bytes) = parse_varint(bytes)
        tx_in = []
        for _ in xrange(num_tx_in):
            (tx, bytes) = TxIn.parse(bytes)
            tx_in.append(tx)
        (num_tx_out, bytes) = parse_varint(bytes)
        tx_out = []
        for _ in xrange(num_tx_out):
            (tx, bytes) = TxOut.parse(bytes)
            tx_out.append(tx)
        ((lock_time,), bytes) = parse(bytes, UINT32_FMT)
        return (cls(version, tx_in, tx_out, lock_time), bytes)

    @property
    def bytes(self):
        return ''.join([
            struct.pack(UINT32_FMT[0], self.version),
            encode_varint(len(self.tx_in)),
            ''.join(txin.bytes for txin in self.tx_in),
            encode_varint(len(self.tx_out)),
            ''.join(txout.bytes for txout in self.tx_out),
            struct.pack(UINT32_FMT[0], self.lock_time)])

    def __eq__(self, b):
        return (self.version == b.version
                and self.tx_in == b.tx_in
                and self.tx_out == b.tx_out
                and self.lock_time == b.lock_time)

    def __repr__(self):
        return 'Transaction(%s, %r, [%s], [%s], %r)' % (
            binascii.hexlify(self.tx_hash),
            self.version,
            ', '.join(repr(tx) for tx in self.tx_in),
            ', '.join(repr(tx) for tx in self.tx_out),
            self.lock_time)


class TransactionMessage(Message):
    COMMAND = 'tx'

    def __init__(self, tx, header=None):
        super(TransactionMessage, self).__init__(header=header)
        self.tx = tx

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        (tx, bytes) = Transaction.parse(bytes)
        return (cls(tx, header), bytes)

    @property
    def payload(self):
        return self.tx.bytes

    def __eq__(self, b):
        return self.tx == b.tx

    def __repr__(self):
        return 'TransactionMessage(%r, %r)' % (self.header, self.tx)


class Block(Message):
    COMMAND = 'block'

    HDR_FMT = fmt_w_size('<I32s32sIII')

    def __init__(self, version, prev_block_hash, merkle_root, timestamp, bits, nonce, txns, header=None):
        super(Block, self).__init__(header=header)
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.txns = txns

    @property
    def block_header(self):
        return struct.pack(
            self.HDR_FMT[0],
            self.version,
            self.prev_block_hash,
            self.merkle_root,
            self.timestamp,
            self.bits,
            self.nonce)

    @property
    def block_hash(self):
        return sha256(sha256(self.block_header).digest()).digest()

    @property
    def payload(self):
        return ''.join(
            [self.block_header,
             encode_varint(len(self.txns)),
             ''.join(tx.bytes for tx in self.txns)])

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        ((version, prev_block_hash, merkle_root, timestamp, bits, nonce),
         bytes) = parse(bytes, cls.HDR_FMT)
        (num_tx, bytes) = parse_varint(bytes)
        txns = []
        for _ in xrange(num_tx):
            (tx, bytes) = Transaction.parse(bytes)
            txns.append(tx)
        return (cls(version, prev_block_hash, merkle_root, timestamp, bits, nonce, txns), bytes)

    def __eq__(self, b):
        return (self.version == b.version
                and self.prev_block_hash == b.prev_block_hash
                and self.merkle_root == b.merkle_root
                and self.timestamp == b.timestamp
                and self.bits == b.bits
                and self.nonce == b.nonce
                and self.txns == b.txns)

    def __repr__(self):
        txins = 0
        txouts = 0
        for tx in self.txns:
            txins += len(tx.tx_in)
            txouts += len(tx.tx_out)
        return 'Block(%u txns, %u txins, %u txouts, %r, %s, %s, %r, %r, %r, %r)' % (
            len(self.txns),
            txins,
            txouts,
            self.version,
            binascii.hexlify(self.prev_block_hash),
            binascii.hexlify(self.merkle_root),
            self.timestamp,
            self.bits,
            self.nonce,
            self.txns)


class GetBlocks(Message):
    COMMAND = 'getblocks'
    HASH_FMT = fmt_w_size('<32s')

    def __init__(self, version, hashes, hash_stop, header=None):
        super(GetBlocks, self).__init__(header=header)
        self.version = version
        self.hashes = hashes
        self.hash_stop = hash_stop

    @property
    def payload(self):
        return ''.join([
            struct.pack(UINT32_FMT[0], self.version),
            encode_varint(len(self.hashes)),
            ''.join(struct.pack(self.HASH_FMT[0], hash) for hash in self.hashes),
            struct.pack(self.HASH_FMT[0], self.hash_stop),
            ])

    @classmethod
    def parse(cls, bytes, header=None):
        if header is None:
            (header, bytes) = MessageHeader.parse(bytes)
        ((version,), bytes) = parse(bytes, UINT32_FMT)
        (num_hashes, bytes) = parse_varint(bytes)
        hashes = []
        for _ in xrange(num_hashes):
            ((hash,), bytes) = parse(bytes, cls.HASH_FMT)
            hashes.append(hash)
        ((hash_stop,), bytes) = parse(bytes, cls.HASH_FMT)
        return (cls(version, hashes, hash_stop, header=header), bytes)

    def __eq__(self, b):
        return (self.version == b.version
                and self.hashes == b.hashes
                and self.hash_stop == b.hash_stop)

    def __repr__(self):
        return 'GetBlocks(%r, %r, %s, %s)' % (
            self.header,
            self.version,
            '[%s]' % (', '.join(binascii.hexlify(hash) for hash in self.hashes)),
            binascii.hexlify(self.hash_stop))


class GetHeaders(GetBlocks):
    COMMAND = 'getheaders'


class Headers(Message):
    COMMAND = 'headers'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


class GetAddresses(Message):
    COMMAND = 'getaddr'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


class CheckOrder(Message):
    COMMAND = 'checkorder'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


class SubmitOrder(Message):
    COMMAND = 'submitorder'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


class Reply(Message):
    COMMAND = 'reply'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


class Alert(Message):
    COMMAND = 'alert'

    def __init__(self):
        raise Error('Unimplemented')

    @classmethod
    def parse(cls, bytes, header=None):
        raise Error('Unimplemented')


COMMAND_CLASS_MAP = {
    cls.COMMAND: cls for cls in
    [
        Version,
        Verack,
        Ping,
        Pong,
        Inventory,
        AddressList,
        TransactionMessage,
        Block,
        GetBlocks,
        GetHeaders,
        Headers,
        GetAddresses,
        CheckOrder,
        SubmitOrder,
        Reply,
        Alert,
    ]
}
