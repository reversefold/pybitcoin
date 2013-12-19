#!/usr/bin/env python
#import greenhouse.emulation
#greenhouse.emulation.patch()

#import os
#import sys
#if hasattr(sys.stdout, 'fileno'):
#    # Force stdout/stderr to be line-buffered
#    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)
#    sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 1)

import binascii
import logging
import logging.config
import os
#import threading
import time

log = logging.getLogger(__name__)


def main():
    logging.config.fileConfig('logging.ini')

    if not os.path.exists('blocktmp'):
        os.mkdir('blocktmp')

    # imported here to make sure logging is set up
    from pybitcoin import io
    ioloop = io.IOLoop()
    from pybitcoin import db

    try:
        #ioloop_thread = threading.Thread(target=ioloop)
        #ioloop_thread.start()
        log.info('Starting pybitcoin ioloop')
        ioloop.start()
        #tx_hash = binascii.unhexlify('63c72b003e92e429fa02bcf57adc2a1bdd088ae4d86745e1d41984323500075f')
        #log.info('Asking for transaction %s', binascii.hexlify(tx_hash))
        #tx = ioloop.get_transaction(tx_hash)
        #log.info('Got transaction: %r', tx)
        while True:
            time.sleep(1)
    finally:
        ioloop.shutdown()
        ioloop.join()
        db.session.commit()
    log.info('Exiting')


if __name__ == '__main__':
    main()
