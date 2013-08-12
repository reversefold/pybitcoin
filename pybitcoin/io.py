import binascii
from Queue import Queue
import random
import socket
import threading
import time
import logging
import logging.config

from pybitcoin import db, protocol

log = logging.getLogger(__name__)


class Error(Exception):
    pass


class SocketError(Error):
    pass


class ConnectionClosedError(SocketError):
    pass


class TimeoutError(Error):
    pass


def recv_bytes(sock, num_bytes):
    data_list = []
    remaining_len = num_bytes
    while remaining_len > 0:
        log.debug('read loop %i', remaining_len)
        try:
            buf = sock.recv(remaining_len)
        except socket.error, e:
            if e.errno == 104:
                log.warn('Connection reset by peer')
                buf = None
            else:
                raise
        if not buf:
            raise ConnectionClosedError('Connection closed from the other side while reading')
        log.debug('Got bytes: %s', binascii.hexlify(buf))
        data_list.append(buf)
        remaining_len -= len(buf)
    data = ''.join(data_list)
    if len(data) != num_bytes:
        raise SocketError('Length of data (%r) is not equal to expected length (%r)' % (len(data), num_bytes))
    return data


class IOLoop(threading.Thread):
    def __init__(self):
        super(IOLoop, self).__init__()
        self.sock = None
        self.out_queue = Queue()
        self.waiting_for = {}
        self.stored = {}

    def send_msg(self, msg):
        log.info('Sending %s', msg.header.command)
        log.debug('%r', msg)
        self.sock.sendall(msg.bytes)

    def run(self):
        self.sock = socket.socket()
        try:
            self.sock.connect(('127.0.0.1', 8333))
            # 70001
#            outmsg = protocol.Version(60002, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), random.getrandbits(32), '/PyBitCoin:0.0.1/', 0)
            outmsg = protocol.Version(70000, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), random.getrandbits(32), '/PyBitCoin:0.0.1/', 0)
            self.send_msg(outmsg)
            while True:
                while not self.out_queue.empty():
                    outmsg = self.out_queue.get()
                    self.send_msg(outmsg)

                hdr_bytes = recv_bytes(self.sock, protocol.MessageHeader.HEADER_FMT[1])
                (hdr, _) = protocol.MessageHeader.parse(hdr_bytes)
                assert not _, _
                payload_bytes = recv_bytes(self.sock, hdr.payload_length)
                (inmsg, _) = protocol.Message.parse(payload_bytes, hdr)
                assert not _, _
                if inmsg is None:
                    log.warn('No parser for command %r, skipping', hdr.command)
                log.debug('Received %s' % (inmsg.header.command,))
                log.debug('%r', inmsg)
                #print bc.visual2(inmsg)
                outmsg = self.handle_message(inmsg)
                if outmsg:
                    self.out_queue.put(outmsg)

        finally:
            try:
                self.sock.shutdown(socket.SHUTDOWN_RDWR)
            except:
                pass
            try:
                self.sock.close()
            except:
                pass


    def handle_default(self, msg):
        log.warn('No handler for %s message', msg.header.command)

    def handle_verack(self, msg):
        log.info('Handling verack %r', msg)
        self.get_missing_blocks()
        self.num_blocks = db.session.query(db.Block).count()
        log.info('Block database has %r blocks', self.num_blocks)

    def get_missing_blocks(self):
        log.info('Requesting missing blocks')
        for (block_hash,) in db.session.connection().execute('select prev_block_hash from block where prev_block_hash not in (select block_hash from block);'):
            self.get_block(bytes(block_hash))

    def handle_ping(self, msg):
        log.info('Handling ping %r', msg)

    def handle_version(self, msg):
        log.info('Handling version %r', msg)
        return protocol.Verack()

    def handle_inv(self, msg):
        log.info('Handling inv %r', msg)
        return protocol.GetData(msg.hashes)

    def get_block(self, block_hash):
        self.out_queue.put(protocol.GetData([(protocol.InventoryVector.MSG_BLOCK, block_hash)]))

    def get_transaction(self, tx_hash):
        item = (protocol.InventoryVector.MSG_TX, tx_hash)
        if item in self.stored:
            return self.stored[item]
        if item not in self.waiting_for:
            event = self.waiting_for[item] = threading.Event()
        else:
            event = self.waiting_for[item]
        self.out_queue.put(protocol.GetData([item]))
        start = time.time()
        while True:
            if not event.wait(5):
                break
            log.debug('Still waiting for tx %s', binascii.hexlify(tx_hash))
            now = time.time()
            if now - start > 30:
                log.info('Waited 30s for tx %s, re-requesting', binascii.hexlify(tx_hash))
                self.out_queue.put(protocol.GetData([item]))
                start = now
        return self.stored[item]

    def handle_tx(self, msg):
#        db.session.add(db.Transaction.from_protocol(msg.tx))
#        db.session.commit()
        tx_hash = msg.tx.tx_hash()
        hashhex = binascii.hexlify(tx_hash)
        log.info('Handling TX %s', hashhex)
        event = self.waiting_for.get((protocol.InventoryVector.MSG_TX, tx_hash))
        if not event:
            return
        log.debug('Someone is waiting for tx %s', hashhex)
        self.stored[(protocol.InventoryVector.MSG_TX, tx_hash)] = msg.tx
        event.set()

    def handle_block(self, msg):
        db.session.add(db.Block.from_protocol(msg))
        db.session.commit()
        self.num_blocks += 1
        log.info('Block database has %r blocks', self.num_blocks)
        block_hash = msg.block_hash
        hashhex = binascii.hexlify(block_hash)
        log.info('Handling Block %s', hashhex)
        if not db.session.query(db.Block).filter(db.Block.block_hash == msg.prev_block_hash).first():
            log.info('Previous block not found %s' % (binascii.hexlify(msg.prev_block_hash),))
            self.get_block(msg.prev_block_hash)

    def handle_message(self, msg):
        handle_name = 'handle_' + msg.COMMAND
        if hasattr(self, handle_name):
            return getattr(self, handle_name)(msg)
        return self.handle_default(msg)
