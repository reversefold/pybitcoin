#!/usr/bin/env python
from __future__ import print_function
from datetime import datetime
import os
import multiprocessing
import Queue
import sys
import threading
import time

from reversefold.util import chunked

from pybitcoin import db


sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)


SQL = """
UPDATE txin SET txout_id = txout.id
FROM txout
JOIN transaction tx ON txout.transaction_id = tx.id
WHERE tx.tx_hash = txin.previous_output_transaction_hash
AND txout.transaction_index = txin.previous_output_index
AND txin.txout_id IS NULL
AND txin.id IN (%s)
"""

BLOCK = 100


class TxInUpdater(object):
    def __init__(self):
        self.db_session = db.Session()
        self.queue = multiprocessing.Queue()
        self.num_processed = multiprocessing.Value('i', 0)
        self.total_to_process = self.db_session.query(db.TxIn.id).filter(
            db.TxIn.txout_id.is_(None)
            & (db.TxIn.previous_output_transaction_hash != 32 * '\x00')
        ).count()
        self.total_blocks = self.total_to_process / BLOCK
        self.blocks_processed = multiprocessing.Value('i', 0)
        self.shutdown_event = multiprocessing.Event()
        self.queued_blocks = 0
        self.start_time = datetime.now()

    def process_chunk(self, txin_ids):
        query_start = datetime.now()
        with db.engine.begin() as conn:
            res = conn.execute(SQL % (', '.join(str(i) for i in txin_ids),))
        query_end = datetime.now()
        tot_time = query_end - self.start_time
        with self.num_processed.get_lock():
            self.num_processed.value += res.rowcount
        with self.blocks_processed.get_lock():
            self.blocks_processed.value += 1
            blocks_processed = self.blocks_processed.value
        avg_time = tot_time / blocks_processed
        print('%u / %u %.3f%% done, %u matched, %s for query, %s total, %s avg, ~%s remaining' % (
            blocks_processed,
            self.total_blocks,
            blocks_processed * 100.0 / self.total_blocks,
            res.rowcount,
            query_end - query_start,
            tot_time,
            avg_time,
            avg_time * (self.total_blocks - blocks_processed)))

    def process_chunks(self):
        while not self.shutdown_event.is_set():
            try:
                chunk = self.queue.get(timeout=1)
                self.process_chunk(chunk)
            except Queue.Empty:
                continue

    def queue_blocks(self):
        if self.total_to_process == 0:
            print('Nothing to queue')
            return
        txin_ids = self.db_session.query(db.TxIn.id).filter(
            db.TxIn.txout_id.is_(None)
            & (db.TxIn.previous_output_transaction_hash != 32 * '\x00')
        ).yield_per(BLOCK).enable_eagerloads(False)

        for chunk in chunked(txin_ids, BLOCK):
            self.queue.put([txin_id for (txin_id,) in chunk])
            self.queued_blocks += 1
            if self.queued_blocks % 1000 == 0:
                print('%r queued' % (self.queued_blocks,))

    def run(self):
        try:
            self.queue_thread = threading.Thread(target=self.queue_blocks)
            self.queue_thread.start()
            procs = []
            for i in xrange(multiprocessing.cpu_count()):
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


def main():
    TxInUpdater().run()


if __name__ == '__main__':
    main()
