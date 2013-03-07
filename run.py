#!/usr/bin/env python
import greenhouse.emulation
greenhouse.emulation.patch()

import logging
import logging.config
#import threading

from greenhouse import scheduler


log = logging.getLogger(__name__)


def main():
    logging.config.fileConfig('logging.ini')

    from pybitcoin import io

#    ioloop_thread = threading.Thread(target=ioloop)
#    ioloop_thread.start()
    log.info('Scheduling pybitcoin ioloop')
    scheduler.schedule(io.ioloop)
    tx_hash = '8a09412745e4138ec58d68ef614303c37a588e459ce36be79c33afb2feb4c746'.decode('hex')
    log.info('Asking for transaction %s' % (tx_hash.encode('hex'),))
    tx = io.get_transaction(tx_hash)
    log.info('Got transaction: %r' % (tx,))
    log.info('Exiting')


if __name__ == '__main__':
    main()
