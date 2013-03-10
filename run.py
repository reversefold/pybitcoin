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
    tx_hash = '6bb14743792a481e7b15a1b5d73a7fb58943efdd61e3599ebd08d8d5fb2d3bf1'.decode('hex')
    log.info('Asking for transaction %s', tx_hash.encode('hex'))
    tx = io.get_transaction(tx_hash)
    log.info('Got transaction: %r', tx)
    log.info('Exiting')


if __name__ == '__main__':
    main()
