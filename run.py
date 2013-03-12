#!/usr/bin/env python
import greenhouse.emulation
greenhouse.emulation.patch()

import logging
import logging.config
#import threading


log = logging.getLogger(__name__)


def main():
    logging.config.fileConfig('logging.ini')

    # imported here to make sure logging is set up
    from pybitcoin import io

    #ioloop_thread = threading.Thread(target=ioloop)
    #ioloop_thread.start()
    log.info('Starting pybitcoin ioloop')
    ioloop = io.IOLoop()
    ioloop.start()
    tx_hash = '63c72b003e92e429fa02bcf57adc2a1bdd088ae4d86745e1d41984323500075f'.decode('hex')
    log.info('Asking for transaction %s', tx_hash.encode('hex'))
    tx = ioloop.get_transaction(tx_hash)
    log.info('Got transaction: %r', tx)
    log.info('Exiting')


if __name__ == '__main__':
    main()
