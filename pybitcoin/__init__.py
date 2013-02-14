"""PyBitCoin"""
import logging

from pybitcoin import protocol


log = logging.getLogger(__name__)


class Error(Exception):
    pass


def handle_default(msg):
    log.warn('No handler for %s message' % (msg.header.command,))


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
