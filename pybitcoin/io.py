import binascii
import datetime
import multiprocessing
import os
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
        self.max_height = multiprocessing.Value('i', 0)
        self.known_blocks = set(block.block_hash for block in db.session.query(db.Block.block_hash).all())
        self.num_blocks = multiprocessing.Value('i', len(self.known_blocks))
        log.info('Block database starting with %r blocks', self.num_blocks.value)

        self.process_queue = Queue()

        self.block_queue = multiprocessing.Queue()
        self.db_write_thread_stop_event = multiprocessing.Event()

        self.process_thread = None
        self.write_thread = None
        self.read_thread = None

        self.shutdown_event = multiprocessing.Event()
        self._internal_shutdown_event = threading.Event()

    def shutdown(self):
        if self.shutdown_event.is_set():
            return
        self.shutdown_event.set()

    def send_msg(self, msg):
        log.debug('Sending %s', msg.header.command)
        log.debug('%r', msg)
        self.sock.sendall(msg.bytes)

    def run(self):
        db_write_thread = multiprocessing.Process(target=self.db_write_loop)
        db_write_thread.start()
        try:
            self._do_run()
        finally:
            self.db_write_thread_stop_event.set()
            db_write_thread.join()

    def _do_run(self):
        while not self.shutdown_event.is_set():
            self.process_thread = threading.Thread(target=self.process_loop)
            self.process_thread.start()
            self.write_thread = threading.Thread(target=self.write_loop)
            self.write_thread.start()
            self.read_thread = threading.Thread(target=self.read_loop)
            self.read_thread.start()
            try:
                self.sock = socket.socket()
                try:
                    self.sock.connect(('127.0.0.1', 8333))
                    #self.sock.connect(('10.0.76.98', 8333))
                    # 70001
                    outmsg = protocol.Version(70000, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), random.getrandbits(32), '/PyBitCoin:0.0.2/', 0)
                    self.out_queue.put(outmsg)

                    while not self.shutdown_event.is_set():
                        self.read_thread.join(0.5)
                        if not self.read_thread.isAlive():
                            break
                        self.process_thread.join(0.5)
                        if not self.process_thread.isAlive():
                            break
                        self.write_thread.join(0.5)
                        if not self.write_thread.isAlive():
                            break

                finally:
                    try:
                        self.sock.shutdown(socket.SHUTDOWN_RDWR)
                    except:
                        pass
                    try:
                        self.sock.close()
                    except:
                        pass
                    self.sock = None
                    self._internal_shutdown_event.set()
                    try:
                        self.read_thread.join()
                    except:
                        pass
                    try:
                        self.process_thread.join()
                    except:
                        pass
                    try:
                        self.write_thread.join()
                    except:
                        pass
                    self._internal_shutdown_event.clear()
            except Exception:
                log.exception('Exception in IO loop, reconnecting')

    def process_loop(self):
        try:
            while True:
                if self._internal_shutdown_event.is_set():
                    return
                #print bc.visual2(inmsg)
                inmsg = self.process_queue.get()
                outmsg = self.handle_message(inmsg)
                if outmsg:
                    self.out_queue.put(outmsg)
        except Exception:
            log.exception('Exception in process_loop')
            self.shutdown()
            raise

    def write_loop(self):
        try:
            while True:
                if self._internal_shutdown_event.is_set():
                    return
                if self.sock is None:
                    time.sleep(1)
                    continue
                outmsg = self.out_queue.get()
                self.send_msg(outmsg)
        except Exception:
            log.exception('Exception in write_loop')
            self.shutdown()
            raise

    def read_loop(self):
        try:
            while True:
                if self._internal_shutdown_event.is_set():
                    return
                if self.sock is None:
                    time.sleep(1)
                    continue
                hdr_bytes = recv_bytes(self.sock, protocol.MessageHeader.HEADER_FMT[1])
                (hdr, _) = protocol.MessageHeader.parse(hdr_bytes)
                assert not _, _
                payload_bytes = recv_bytes(self.sock, hdr.payload_length)
                (inmsg, _) = protocol.Message.parse(payload_bytes, hdr)
                assert not _, _
                if inmsg is None:
                    log.warn('No parser for command %r, skipping', hdr.command)
                log.debug('Received %s', inmsg.header.command)
                log.debug('%r', inmsg)
                self.process_queue.put(inmsg)
        except Exception:
            log.exception('Exception in read_loop')
            self.shutdown()
            raise

    def handle_default(self, msg):
        log.debug('No handler for %s message', msg.header.command)

    def handle_verack(self, msg):
        log.info('Handling verack %r', msg)
        self.get_missing_blocks()

    def get_missing_blocks(self):
        log.info('Calculating missing blocks')
        prev_block_hashes = set(block.prev_block_hash for block in db.session.query(db.Block.prev_block_hash).all())
        missing_block_hashes = prev_block_hashes - self.known_blocks - set([32 * '\x00'])
        if missing_block_hashes:
            log.info('Requesting %d missing blocks', len(missing_block_hashes))
            for block_hash in missing_block_hashes:
                self.get_block(bytes(block_hash))
        else:
            log.info('No blocks missing from the stored blockchain')

    def handle_ping(self, msg):
        log.info('Handling ping %r', msg)

    def handle_version(self, msg):
        log.info('Handling version %r', msg)
        self.max_height.value = msg.start_height
        return protocol.Verack()

    def handle_inv(self, msg):
        log.debug('Handling inv %r', msg)
        block_hashes = []
        for entry in msg.hashes:
            if entry[0] == protocol.InventoryVector.MSG_BLOCK:
                block_hashes.append(entry)
        if block_hashes:
            log.info('Requesting blocks [%s]', ', '.join(binascii.hexlify(block_hash) for (_, block_hash) in block_hashes))
            return protocol.GetData(block_hashes)

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
        tx_hash = msg.tx.tx_hash
        hashhex = binascii.hexlify(tx_hash)
        log.info('Handling TX %s', hashhex)
#        db.session.add(db.Transaction.from_protocol(msg.tx))
#        db.session.commit()
        event = self.waiting_for.get((protocol.InventoryVector.MSG_TX, tx_hash))
        if not event:
            return
        log.debug('Someone is waiting for tx %s', hashhex)
        self.stored[(protocol.InventoryVector.MSG_TX, tx_hash)] = msg.tx
        event.set()

    def handle_block(self, msg):
        block_hash = msg.block_hash
        hashhex = binascii.hexlify(block_hash)
        txins = 0
        txouts = 0
        for tx in msg.txns:
            txins += len(tx.tx_in)
            txouts += len(tx.tx_out)
        log.info('Handling Block %s %u txns %u txins %u txouts', hashhex, len(msg.txns), txins, txouts)

        #if db.session.query(db.Block).filter(db.Block.block_hash == msg.prev_block_hash).first():

        self.known_blocks.add(msg.block_hash)

        if msg.prev_block_hash in self.known_blocks:
            self.max_height.value += 1
        else:
            log.info('Previous block not found %s', binascii.hexlify(msg.prev_block_hash))
            self.get_block(msg.prev_block_hash)

        blktmpfilename = 'blocktmp/' + hashhex + '.rawblk'
        log.info('Queueing block, writing to disk %s', blktmpfilename)
        with open(blktmpfilename, 'w') as blktmpfile:
            blktmpfile.write(msg.bytes)
        self.block_queue.put(blktmpfilename)

        log.info('Block database has %d/%d blocks (%d queued)', self.num_blocks.value, self.max_height.value, self.block_queue.qsize())

    def write_block_to_db(self, msg):
        hexhash = binascii.hexlify(msg.block_hash)
        log.info('Writing block %s to DB', hexhash)
        self.num_blocks.value += 1
        db.session.add(db.Block.from_protocol(msg))
        #db.Block.from_protocol(msg).bulk_insert(db.session)
        log.debug('Flushing DB session')
        start = datetime.datetime.now()
        db.session.flush()
        log.debug('DB Flush took %s', datetime.datetime.now() - start)
        self.known_blocks.add(msg.block_hash)
        log.debug('Committing DB session')
        start = datetime.datetime.now()
        db.session.commit()
        log.debug('DB Commit took %s', datetime.datetime.now() - start)
        log.info('Block %s committed', hexhash)
        log.info('Block database has %d/%d blocks (%d queued)', self.num_blocks.value, self.max_height.value, self.block_queue.qsize())

    def handle_message(self, msg):
        handle_name = 'handle_' + msg.COMMAND
        if hasattr(self, handle_name):
            return getattr(self, handle_name)(msg)
        return self.handle_default(msg)

    def db_write_loop(self):
        try:
            while not self.db_write_thread_stop_event.is_set():
                if self.block_queue.empty():
                    time.sleep(1)
                else:
                    blktmpfilename = self.block_queue.get()
                    log.info('Reading block file %s', blktmpfilename)
                    with open(blktmpfilename, 'r') as blktmpfile:
                        (msg, _) = protocol.Message.parse(blktmpfile.read())
                        assert not _, _
                    os.remove(blktmpfilename)
                    self.write_block_to_db(msg)
        except:
            log.exception('exception in db_write_loop')
            raise
        finally:
            self.shutdown()
