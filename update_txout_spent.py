#!/usr/bin/env python
from __future__ import print_function
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import str
from builtins import range
from builtins import object
from past.utils import old_div
from datetime import datetime
import os
import multiprocessing
import queue
import sys
import threading
import time

from reversefold.util import chunked
from sqlalchemy.sql import functions as sql_functions

from pybitcoin import db


sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

"""
UPDATE txout SET spent=true
FROM txin
WHERE txout.id = txin.txout_id
AND txout.spent IS NULL OR NOT txout.spent
AND txout.id IN (
    SELECT t.txout_id FROM txin t
    JOIN transaction x ON t.transaction_id = x.id
    WHERE x.block_id = :block_id
)
"""


SQL = """
UPDATE txout SET spent=true
FROM txin
WHERE txout.id = txin.txout_id
AND txout.spent IS NULL OR NOT txout.spent
AND txout.id IN (%s)
"""

BLOCK = 1000


class TxOutUpdater(object):
    def __init__(self):
        self.db_session = db.Session()
        #STATEFILE = 'txout_id'
        #if not os.path.exists(STATEFILE):
        #    with open(STATEFILE, 'w') as f:
        #        f.write(str(self.db_session.query(sql_functions.min(db.TxOut.id)).scalar()))
        #with open(STATEFILE, 'r') as f:
        #    self.min_id = int(f.read())
        #self.min_id = 97465110 - BLOCK * 100
        #self.min_id = self.db_session.query(sql_functions.min(db.TxOut.id)).scalar()
        self.queue = multiprocessing.Queue()
        self.num_processed = multiprocessing.Value('i', 0)
        self.total_to_process = self.db_session.query(db.TxOut.id).filter(
            # db.TxOut.id >= self.min_id
            db.TxOut.spent.is_(None) | db.TxOut.spent.is_(False)
        ).count()
        self.total_blocks = old_div(self.total_to_process, BLOCK)
        self.blocks_processed = multiprocessing.Value('i', 0)
        self.shutdown_event = multiprocessing.Event()
        self.queued_blocks = 0
        self.start_time = datetime.now()

    def run(self):
        try:
            self.queue_thread = threading.Thread(target=self.queue_blocks)
            self.queue_thread.start()
            procs = []
            for i in range(multiprocessing.cpu_count()):
                proc = multiprocessing.Process(target=self.process_chunks)
                proc.start()
                procs.append(proc)
            #output = 0
            while not self.queue.empty() or self.queue_thread.is_alive():
                with self.blocks_processed.get_lock():
                    blocks_processed = self.blocks_processed.value

                tot_time = datetime.now() - self.start_time
                if blocks_processed == 0:
                    print('%s' % (tot_time,))
                    time.sleep(5)
                    continue

                #avg_time = tot_time / blocks_processed
                #if blocks_processed - output > 20:
                #    output = blocks_processed
                #    print('%u / %u %.3f%% done, %s total, %s avg, ~%s remaining\n' % (
                #        blocks_processed,
                #        self.total_blocks,
                #        blocks_processed * 100.0 / self.total_blocks,
                #        tot_time,
                #        avg_time,
                #        avg_time * (self.total_blocks - blocks_processed))
                #    )
                time.sleep(5)
            self.shutdown_event.set()
            self.queue_thread.join()
            for proc in procs:
                proc.join()
        finally:
            self.db_session.flush()
            self.db_session.commit()

    def queue_blocks(self):
        if self.total_to_process == 0:
            print('Nothing to queue')
            return
        txout_ids = self.db_session.query(db.TxOut.id).filter(
            # db.TxOut.id >= self.min_id
            db.TxOut.spent.is_(None) | db.TxOut.spent.is_(False)
        ).yield_per(BLOCK).enable_eagerloads(False)

        for chunk in chunked(txout_ids, BLOCK):
            self.queue.put([txout_id for (txout_id,) in chunk])
            self.queued_blocks += 1
            if self.queued_blocks % 1000 == 0:
                print('%r queued' % (self.queued_blocks,))

    def process_chunks(self):
        while not self.shutdown_event.is_set():
            try:
                chunk = self.queue.get(timeout=1)
                self.process_chunk(chunk)
            except queue.Empty:
                continue

    def process_chunk(self, txout_ids):
        query_start = datetime.now()
        with db.engine.begin() as conn:
            res = conn.execute(SQL % (', '.join(str(i) for i in txout_ids),))
        query_end = datetime.now()
        tot_time = query_end - self.start_time
        with self.num_processed.get_lock():
            self.num_processed.value += res.rowcount
        with self.blocks_processed.get_lock():
            self.blocks_processed.value += 1
            blocks_processed = self.blocks_processed.value
        avg_time = old_div(tot_time, blocks_processed)
        print('%u / %u %.3f%% done, %u matched, %s for query, %s total, %s avg, ~%s remaining' % (
            blocks_processed,
            self.total_blocks,
            blocks_processed * 100.0 / self.total_blocks,
            res.rowcount,
            query_end - query_start,
            tot_time,
            avg_time,
            avg_time * (self.total_blocks - blocks_processed)))


def main():
    TxOutUpdater().run()


if __name__ == '__main__':
    main()
