import random
import socket
import threading
import time
import logging
import logging.config

from pybitcoin import protocol

log = logging.getLogger(__name__)


class Error(Exception):
    pass


class SocketError(Error):
    pass


class ConnectionClosedError(SocketError):
    pass


def recv_bytes(sock, num_bytes):
    data_list = []
    remaining_len = num_bytes
    while remaining_len > 0:
        log.debug("read loop %i", remaining_len)
        try:
            buf = sock.recv(remaining_len)
        except socket.error, e:
            if e.errno == 104:
                log.warn("Connection reset by peer")
                buf = None
            else:
                raise
        if not buf:
            raise ConnectionClosedError("Connection closed from the other side while reading")
        data_list.append(buf)
        remaining_len -= len(buf)
    data = ''.join(data_list)
    if len(data) != num_bytes:
        raise SocketError("Length of data (%r) is not equal to expected length (%r)" % (len(data), num_bytes))
    return data


_out_queue = []


sock = None


def ioloop():
    global sock
    sock = socket.socket()
    try:
        sock.connect(('localhost', 8333))
        outmsg = protocol.Version(60002, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), random.getrandbits(32), '/PyBitCoin:0.0.1/', 212672, 1, 1355854353)
        log.info('Sending %s', outmsg.header.command)
        log.debug('%r', outmsg)
        sock.sendall(outmsg.bytes)
        while True:
            hdr_bytes = recv_bytes(sock, protocol.MessageHeader.HEADER_FMT[1])
            (hdr, _) = protocol.MessageHeader.parse(hdr_bytes)
            payload_bytes = recv_bytes(sock, hdr.payload_length)
            (inmsg, _) = protocol.Message.parse(payload_bytes, hdr)
            if inmsg is None:
                log.warn('No parser for command %r, skipping', hdr.command)
                continue
            log.info('Received %s' % (inmsg.header.command,))
            log.debug('%r', inmsg)
            #print bc.visual2(inmsg)
            outmsg = handle_message(inmsg)
            if not outmsg:
                continue
            log.info('Sending %s', outmsg.header.command)
            sock.sendall(outmsg.bytes)

    finally:
        try:
            sock.shutdown(socket.SHUTDOWN_RDWR)
        except:
            pass
        try:
            sock.close()
        except:
            pass


def handle_default(msg):
    log.warn('No handler for %s message' % (msg.header.command,))


def handle_verack(msg):
    pass


def handle_ping(msg):
    pass


def handle_version(msg):
    return protocol.Verack()


def handle_inv(msg):
    return protocol.GetData(msg.hashes)


_waiting_for = {}


def get_transaction(hash):
    item = (protocol.InventoryVector.MSG_TX, hash)
    if item not in _waiting_for:
        event = _waiting_for[item] = threading.Event()
        event.waiting = 0
    else:
        event = _waiting_for[item]
    while True:
        if sock == None:
            log.debug('Waiting for sock...')
            time.sleep(1)
        else:
            break
    sock.sendall(protocol.GetData([item]).bytes)
    event.waiting += 1
    while True:
        if not event.wait(1):
            break
        log.debug('Still waiting for tx %s' % (hash.encode('hex'),))
    event.waiting -= 1
    tx = event.tx
    return tx


def handle_tx(msg):
    # TODO: store?
    hash = msg.tx.hash()
    hashhex = hash.encode('hex')
    event = _waiting_for.get((protocol.InventoryVector.MSG_TX, hash))
    if not event:
        return
    log.debug('Someone is waiting for tx %s' % (hashhex,))
    event.tx = msg.tx
    # TODO: only one will get it? never switch back?
    while True:
        # TODO: needed?
        #if event.waiting > 1:
        #    scheduler.schedule(compat.getcurrent())
        log.debug('%r waiting for tx %s' % (event.waiting, hashhex))
        waiting = event.waiting
        event.set()
        if waiting <= 1:
            log.debug('No more waiting')
            break


COMMAND_HANDLE_MAP = {
    'verack': handle_verack,
    'version': handle_version,
    'ping': handle_ping,
    'inv': handle_inv,
    'tx': handle_tx,
}


def handle_message(msg):
    return COMMAND_HANDLE_MAP.get(msg.header.command, handle_default)(msg)
