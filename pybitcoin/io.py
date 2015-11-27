import binascii
import ctypes
import datetime
import errno
import glob
import multiprocessing
import os
import Queue
import random
import socket
import threading
import time
import logging
import logging.config

import netifaces
from sqlalchemy.sql import functions as sql_functions

from pybitcoin import db, protocol


log = logging.getLogger(__name__)


CONNECT_TIMEOUT = 10
SOCKET_TIMEOUT = 120
SLEEP_BETWEEN_CONNECTS = 300
SECONDS_BETWEEN_PINGS = 60
MESSAGE_TIMEOUT = 60


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
            raise
#            if e.errno == errno.ECONNRESET:
#                log.warn('Connection reset by peer')
#                buf = None
#            else:
#                raise
        if not buf:
            raise ConnectionClosedError('Connection closed from the other side while reading')
        log.debug('Got bytes: %s', binascii.hexlify(buf))
        data_list.append(buf)
        remaining_len -= len(buf)
    data = ''.join(data_list)
    if len(data) != num_bytes:
        raise SocketError('Length of data (%r) is not equal to expected length (%r)' % (len(data), num_bytes))
    return data


class QueueWithQSize(object):
    def __init__(self, *a, **k):
        super(QueueWithQSize, self).__init__(*a, **k)
        self._qsize = multiprocessing.Value(ctypes.c_ulonglong, 0)
        self._queue = multiprocessing.Queue(*a, **k)

    def put(self, *a, **k):
        result = self._queue.put(*a, **k)
        with self._qsize.get_lock():
            self._qsize.value += 1
        return result

    def get(self, *a, **k):
        result = self._queue.get(*a, **k)
        with self._qsize.get_lock():
            self._qsize.value -= 1
        return result

    def empty(self):
        return self._queue.empty()

    def qsize(self):
        with self._qsize.get_lock():
            return self._qsize.value


class IOLoop(threading.Thread):
    def __init__(self, read_blocktmp_files=True):
        super(IOLoop, self).__init__()
        self.sock = None
        self.out_queue = Queue.Queue()
        self.waiting_for = {}
        self.stored = {}
        self.max_height = multiprocessing.Value(ctypes.c_ulong, 0)

        self.db_session = db.Session()

        self.db_write_loop = DBWriteLoop(self)

        max_height = self.db_session.query(sql_functions.max(db.Block.depth)).scalar()
        if max_height is not None:
            self.max_height.value = max_height
        self.known_blocks = set(
            block.block_hash
            for block in self.db_session.query(db.Block.block_hash).all()
        )
        self._prev_block_hashes = set()
        if read_blocktmp_files:
            for blktmpfilename in glob.glob('blocktmp/*.rawblk'):
                self.db_write_loop.queue_block(blktmpfilename)
                log.info('Reading blockfile %s', blktmpfilename)
                try:
                    with open(blktmpfilename, 'rb') as blktmpfile:
                        data = blktmpfile.read()
                except IOError:
                    log.exception('IOError reading blockfile %s', blktmpfilename)
                    continue
                (msg, _) = protocol.Message.parse(data)
                assert not _, _
                self.known_blocks.add(msg.block_hash)
                self._prev_block_hashes.add(msg.prev_block_hash)

        self.num_blocks = multiprocessing.Value(ctypes.c_ulonglong, len(self.known_blocks))
        log.info('Block database starting with %r blocks', self.num_blocks.value)

        self.process_queue = Queue.Queue()

        self.process_thread = None
        self.write_thread = None
        self.read_thread = None

        self.shutdown_event = multiprocessing.Event()
        self._internal_shutdown_event = threading.Event()

        self.message_timeout = MESSAGE_TIMEOUT
        self.ping_timing = SECONDS_BETWEEN_PINGS
        self.last_ping = None
        self.last_pong = None
        self.last_message = None

        self.remote_addr = ('10.0.42.253', 8333)
        self.remote_addr = ('127.0.0.1', 8333)
        local_addr = [
            addrs for i, addrs in
            ((i, [addr for addr in addrs[netifaces.AF_INET] if 'peer' not in addr])
                for i, addrs in
                ((i, netifaces.ifaddresses(i))
                    for i in netifaces.interfaces())
                if netifaces.AF_INET in addrs)
            if addrs
        ][0][0]
        self.local_addr = local_addr['addr']
        self.local_port = 8334

    def shutdown(self):
        if self.shutdown_event.is_set():
            return
        self.shutdown_event.set()

    def _internal_shutdown(self):
        if self._internal_shutdown_event.is_set():
            return
        self._internal_shutdown_event.set()

    def send_msg(self, msg):
        log.info('Sending %s', msg.header.command)
        log.debug('%r', msg)
        self.sock.sendall(msg.bytes)

    def run(self):
        self.db_write_thread = multiprocessing.Process(target=self.db_write_loop.run)
        self.db_write_thread.start()
        try:
            self._do_run()
        finally:
            self.db_write_thread.shutdown()
            self.db_write_thread.join()

    def _do_run(self):
        while not self.shutdown_event.is_set():
            self.last_ping = None
            self.last_pong = None
            log.info('starting threads')
            self.process_thread = threading.Thread(target=self.process_loop)
            self.process_thread.start()
            log.info('process thread started')
            self.write_thread = threading.Thread(target=self.write_loop)
            self.write_thread.start()
            log.info('write thread started')
            self.read_thread = threading.Thread(target=self.read_loop)
            self.read_thread.start()
            log.info('read thread started')
            try:
                #self.sock = socket.socket()
                try:
                    log.info('Connecting')
                    self.sock = socket.create_connection(self.remote_addr, timeout=CONNECT_TIMEOUT)
                    self.sock.settimeout(SOCKET_TIMEOUT)
                    outmsg = protocol.Version(
                        version=protocol.PROTOCOL_VERSION,
                        addr_recv=(1, self.remote_addr[0], self.remote_addr[1]),
                        addr_from=(1, self.local_addr, self.local_port),
                        nonce=random.getrandbits(32),
                        user_agent='/PyBitCoin:0.0.3/',
                        start_height=self.max_height.value,
                        relay=False)
                    self.out_queue.put(outmsg)

                    while not self.shutdown_event.is_set():
                        self.read_thread.join(0.05)
                        if not self.read_thread.isAlive():
                            log.warn('read_thread is dead')
                            break
                        self.process_thread.join(0.05)
                        if not self.process_thread.isAlive():
                            log.warn('process_thread is dead')
                            break
                        self.write_thread.join(0.05)
                        if not self.write_thread.isAlive():
                            log.warn('write_thread is dead')
                            break
                        if self.last_ping is None or time.time() - self.last_ping > self.ping_timing:
                            if self.last_ping is not None and (self.last_pong is None or self.last_pong < self.last_ping):
                                if self.last_message is None or time.time() - self.last_message > self.message_timeout:
                                    raise TimeoutError('No PONG received for ping and no message in %us, connection is stale' % (self.message_timeout,))
                            log.info('Sending a Ping')
                            self.out_queue.put(protocol.Ping())
                            self.last_ping = time.time()

                finally:
                    log.warn('shutting down socket')
                    if self.sock:
                        try:
                            self.sock.shutdown(socket.SHUTDOWN_RDWR)
                        except:
                            pass
                        try:
                            self.sock.close()
                        except:
                            pass
                    self.sock = None
                    log.info('shutting down threads')
                    self._internal_shutdown_event.set()
                    try:
                        self.read_thread.join()
                    except:
                        pass
                    log.info('Read thread joined')
                    try:
                        self.process_thread.join()
                    except:
                        pass
                    log.info('Process thread joined')
                    try:
                        self.write_thread.join()
                    except:
                        pass
                    log.info('Write thread joined')
                    self._internal_shutdown_event.clear()
                    log.info('shutdown finished')
            except Exception:
                log.exception('Exception in IO loop, reconnecting')
                time.sleep(SLEEP_BETWEEN_CONNECTS)
            log.info('End of while loop')
        log.info('End of _do_run')

    def process_loop(self):
        try:
            while True:
                if self._internal_shutdown_event.is_set():
                    return
                #print bc.visual2(inmsg)
                try:
                    inmsg = self.process_queue.get(timeout=1)
                except Queue.Empty:
                    continue
                outmsg = self.handle_message(inmsg)
                if outmsg:
                    self.out_queue.put(outmsg)
        except KeyboardInterrupt:
            log.exception('KeyboardInterrupt in process_loop')
            self.shutdown()
            raise
        except Exception:
            log.exception('Exception in process_loop')
            self._internal_shutdown()
            raise

    def write_loop(self):
        # TODO: Keep track of unacked messages (getdata without a block sent back, etc.)
        try:
            while True:
                if self._internal_shutdown_event.is_set():
                    return
                if self.sock is None:
                    time.sleep(1)
                    continue
                try:
                    outmsg = self.out_queue.get(timeout=1)
                except Queue.Empty:
                    continue
                self.send_msg(outmsg)
        except KeyboardInterrupt:
            log.exception('KeyboardInterrupt in write_loop')
            self.shutdown()
            raise
        except Exception:
            log.exception('Exception in write_loop')
            self._internal_shutdown()
            raise

    def read_loop(self):
        # TODO: Keep track of unacked messages (getdata without a block sent back, etc.)
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
        except KeyboardInterrupt:
            log.exception('KeyboardInterrupt in read_loop')
            self.shutdown()
            raise
        except Exception:
            log.exception('Exception in read_loop')
            self._internal_shutdown()
            raise

    def handle_default(self, msg):
        log.debug('No handler for %s message', msg.header.command)

    def handle_verack(self, msg):
        log.info('Handling verack %r', msg)
        self.get_missing_blocks()

    def get_missing_blocks(self):
        log.info('Calculating missing blocks')
        prev_block_hashes = set(
            block.prev_block_hash
            for block in self.db_session.query(db.Block.prev_block_hash).filter(db.Block.prev_block_id.is_(None)).all()
        ).union(self._prev_block_hashes)
        missing_block_hashes = prev_block_hashes - self.known_blocks - set([32 * '\x00'])
        if missing_block_hashes:
            log.info('Requesting %d missing blocks', len(missing_block_hashes))
            for block_hash in missing_block_hashes:
                self.get_block(bytes(block_hash))
        else:
            log.info('No blocks missing from the stored blockchain')
        ## TODO: implement merkle-root syncing with the other side, possibly via GetBlocks

    def handle_ping(self, msg):
        log.info('Handling ping %r', msg)
        return protocol.Pong()

    def handle_pong(self, msg):
        log.info('Handling pong %r', msg)
        self.last_pong = time.time()

    def handle_version(self, msg):
        log.info('Handling version %r', msg)
        #self.max_height.value = msg.start_height
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
#        self.db_session.add(db.Transaction.from_protocol(msg.tx))
#        self.db_session.commit()
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

        if block_hash in self.known_blocks:
            log.info('Block already known')
            return

        #if self.db_session.query(db.Block).filter(db.Block.block_hash == msg.prev_block_hash).first():

        self.known_blocks.add(block_hash)
        self._prev_block_hashes.add(msg.prev_block_hash)

        if msg.prev_block_hash in self.known_blocks:
            # TODO: This is incorrect, we need to calculate this based on the depth values in the Block
            #self.max_height.value += 1
            pass
        else:
            log.info('Previous block not found %s', binascii.hexlify(msg.prev_block_hash))
            self.get_block(msg.prev_block_hash)

        blktmpfilename = 'blocktmp/' + hashhex + '.rawblk'
        if not os.path.exists(blktmpfilename):
            log.info('Queueing block, writing to disk %s', blktmpfilename)
            with open(blktmpfilename, 'wb') as blktmpfile:
                blktmpfile.write(msg.bytes)
            self.db_write_loop.queue_block(blktmpfilename)
        else:
            log.info('Block already written to disk %s', blktmpfilename)

        #self.write_block_to_db(msg)

        log.info('Block database has %d/%d blocks (%d queued)', self.num_blocks.value, self.max_height.value, self.db_write_loop.num_queued_blocks())

    def handle_message(self, msg):
        self.last_message = time.time()
        handle_name = 'handle_' + msg.COMMAND
        if hasattr(self, handle_name):
            return getattr(self, handle_name)(msg)
        return self.handle_default(msg)


class DBWriteLoop(object):
    def __init__(self, ioloop):
        self.ioloop = ioloop
        self.db_write_thread_stop_event = multiprocessing.Event()
        self.block_queue = QueueWithQSize()
        self.db_session = None

    def shutdown(self):
        return self.db_write_thread_stop_event.set()

    def queue_block(self, blktmpfilename):
        return self.block_queue.put(blktmpfilename)

    def num_queued_blocks(self):
        return self.block_queue.qsize()

    def write_block_to_db(self, msg):
        if self.db_session.query(sql_functions.count(db.Block.block_hash)).filter(db.Block.block_hash == msg.block_hash).scalar():
            log.warning('Block already in DB, skipping')
            return

        hexhash = binascii.hexlify(msg.block_hash)
        txins = 0
        txouts = 0
        for tx in msg.txns:
            txins += len(tx.tx_in)
            txouts += len(tx.tx_out)
        log.info('Writing Block %s to DB %u txns %u txins %u txouts', hexhash, len(msg.txns), txins, txouts)
        self.ioloop.num_blocks.value += 1
        #self.db_session.begin()
        db_block = db.Block.from_protocol(msg)
        self.db_session.add(db_block)
        #db.Block.from_protocol(msg).bulk_insert(self.db_session)

        # TODO: Allow this to be turned off when doing intial block import
        log.info('Updating block metadata')
        db_block.update_metadata(self.db_session)

        log.debug('Flushing DB session')
        start = datetime.datetime.now()
        self.db_session.flush()
        log.debug('DB Flush took %s', datetime.datetime.now() - start)
        self.ioloop.known_blocks.add(msg.block_hash)
        log.debug('Committing DB session')
        start = datetime.datetime.now()
        self.db_session.commit()
        log.debug('DB Commit took %s', datetime.datetime.now() - start)
        log.info('Block %s committed', hexhash)
        log.info(
            'Block database has %d/%d blocks (%d queued)',
            self.ioloop.num_blocks.value, self.ioloop.max_height.value, self.num_queued_blocks()
        )

    def run(self):
        self.db_session = db.Session()
        try:
            while not self.db_write_thread_stop_event.is_set():
                try:
                    if self.block_queue.empty():
                        time.sleep(1)
                    else:
                        try:
                            blktmpfilename = self.block_queue.get(timeout=1)
                        except Queue.Empty:
                            continue
                        log.info('Reading block file %s', blktmpfilename)
                        try:
                            with open(blktmpfilename, 'rb') as blktmpfile:
                                data = blktmpfile.read()
                        except IOError:
                            log.exception('IOError reading blockfile %s', blktmpfilename)
                            continue
                        (msg, _) = protocol.Message.parse(data)
                        assert not _, _
                        self.write_block_to_db(msg)
                        os.remove(blktmpfilename)
                except Exception:
                    log.exception('Exception in db_write_loop, creating a new session')
                    self.block_queue.put(blktmpfilename)
                    try:
                        db.reconnect()
                    except Exception:
                        log.exception('Exception reconnecting, ignoring')
                    log.info('Reconnected')
                except:
                    self.block_queue.put(blktmpfilename)
                    raise
        except:
            log.exception('exception in db_write_loop')
            raise
        finally:
            log.info('db_write_loop shutting down IOLoop')
            self.ioloop.shutdown()
            log.info('db_write_loop finished')
