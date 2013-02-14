#!/usr/bin/env python
from gevent import monkey
monkey.patch_all()

import logging
import logging.config
import socket

import pybitcoin as bc
from pybitcoin import protocol


log = logging.getLogger(__name__)


class SocketError(Exception):
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


def main():
    logging.config.fileConfig('logging.ini')
    sock = socket.socket()
    try:
        sock.connect(('localhost', 8333))
        outmsg = protocol.Version(60002, (1, '0.0.0.0', 0), (1, '0.0.0.0', 0), 7284544412836900411, '/PyBitCoin:0.0.1/', 212672, 1, 1355854353)
        log.info('Sending %s' % (outmsg.header.command,))
        sock.sendall(outmsg.bytes)
        while True:
            hdr_bytes = recv_bytes(sock, protocol.MessageHeader.HEADER_FMT[1])
            (hdr, _) = protocol.MessageHeader.parse(hdr_bytes)
            payload_bytes = recv_bytes(sock, hdr.payload_length)
            (inmsg, _) = protocol.Message.parse(payload_bytes, hdr)
            if inmsg is None:
                log.warn('No parser for command %r, skipping' % (hdr.command,))
                continue
            log.info('Received %s' % (inmsg.header.command,))
            log.debug(repr(inmsg))
            #print bc.visual2(inmsg)
            outmsg = bc.handle_message(inmsg)
            if not outmsg:
                continue
            log.info('Sending %s' % (outmsg.header.command,))
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


if __name__ == '__main__':
    main()
