"""PyBitCoin"""
import logging

from pybitcoin import protocol


log = logging.getLogger(__name__)


class Error(Exception):
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


def handle_default(msg):
    log.info('No handler for %s message' % (msg.header.command,))


def handle_verack(msg):
    pass


def handle_ping(msg):
    pass


def handle_version(msg):
    return protocol.Verack()


COMMAND_HANDLE_MAP = {
    'verack': handle_verack,
    'version': handle_version,
    'ping': handle_ping,
}


def handle_message(msg):
    return COMMAND_HANDLE_MAP.get(msg.header.command, handle_default)(msg)
