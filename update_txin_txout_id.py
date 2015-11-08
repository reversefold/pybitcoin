#!/usr/bin/env python
import binascii
from datetime import datetime
import os
import multiprocessing
import Queue
from sqlalchemy import func
import sys
import threading
import time

from pybitcoin import db
from pybitcoin.key import encode_bigint

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)


#SQL = """UPDATE txin SET txout_id = txout.id
#FROM txout JOIN transaction t ON txout.transaction_id = t.id
#WHERE t.tx_hash = txin.previous_output_transaction_hash
#AND txout.transaction_index = txin.previous_output_index AND txin.txout_id IS NULL"""
#
#BLOCK = 1000
#
#def main():
#    max_id = db.session.query(func.max(db.TxIn.id)).scalar()
#    cur_id = 0
#    start_time = datetime.now()
#    while cur_id <= max_id:
#        end_id = cur_id + BLOCK
#        print 'Updating %u - %u / %u' % (cur_id, end_id, max_id)
#        query_start = datetime.now()
#        db.engine.execute(SQL + ' AND txin.id >= %u AND txin.id < %u' % (cur_id, end_id))
#        query_end = datetime.now()
#        cur_id = end_id
#        tot_time = query_end - start_time
#        print '%u/%u done, %s for query, %s total, ~%s remaining' % (cur_id, max_id, query_end - query_start, tot_time, tot_time * max_id / cur_id)

#SQL = """
#UPDATE txin SET txout_id = txout.id
#FROM txout JOIN transaction t ON txout.transaction_id = t.id
#WHERE t.tx_hash = txin.previous_output_transaction_hash
#AND txout.transaction_index = txin.previous_output_index AND txin.txout_id IS NULL
#AND t.id >= %s AND t.id < %s
#"""
#
#BLOCK = 1000
#
#def main():
#    max_id = db.session.query(func.max(db.Transaction.id)).scalar()
#    min_id = 22000
#    cur_id = min_id
#    start_time = datetime.now()
#    while cur_id <= max_id:
#        end_id = cur_id + BLOCK
#        print 'Updating %u - %u / %u' % (cur_id, end_id, max_id)
#        query_start = datetime.now()
#        with db.engine.begin() as conn:
#            res = conn.execute(SQL, (cur_id, end_id))
#        query_end = datetime.now()
#        cur_id = end_id
#        tot_time = query_end - start_time
#        print '%.2f%% done, %u matched, %s for query, %s total, ~%s remaining' % (((cur_id - min_id) * 100.0 / (max_id - min_id)), res.rowcount, query_end - query_start, tot_time, tot_time * ((max_id - min_id) / (cur_id - min_id)))

#SQL = """
#UPDATE txin SET txout_id = txout.id
#FROM txout JOIN tx_hash_lookup t ON txout.transaction_id = t.id
#WHERE t.tx_hash = txin.previous_output_transaction_hash
#AND txout.transaction_index = txin.previous_output_index AND txin.txout_id IS NULL
#AND t.tx_hash >= %s AND t.tx_hash < %s
#"""
#
##SQL = """
##UPDATE txin SET txout_id = txout.id
##FROM txout JOIN transaction t ON txout.transaction_id = t.id
##WHERE t.tx_hash = txin.previous_output_transaction_hash
##AND txout.transaction_index = txin.previous_output_index AND txin.txout_id IS NULL
##AND t.tx_hash >= %s AND t.tx_hash < %s
##"""
#
#BLOCK = 1  #int('ff' * 32, base=16) / 100000
#BLOCK = 50000000000000000000000000000000000000000000000000000000000000000000000
#
#def main():
#    max_id = int('ff' * 32, base=16)  #db.session.query(func.max(db.Transaction.id)).scalar()
#    min_id = int('017a939d04e2f4ff93c2dfcdb414b8d92bc3eca2d605407aa77e631803c239b4', base=16)
#    cur_id = min_id
#    start_time = datetime.now()
#    while cur_id <= max_id:
#        end_id = cur_id + BLOCK
#        print 'Updating %064x - %064x' % (cur_id, end_id)
#        #print 'Updating %064s - %064s / %064s' % (binascii.hexlify(encode_bigint(cur_id)), binascii.hexlify(encode_bigint(end_id)), binascii.hexlify(encode_bigint(max_id)))
#        query_start = datetime.now()
#        with db.engine.begin() as conn:
#            res = conn.execute(SQL, (bytearray(encode_bigint(cur_id)), bytearray(encode_bigint(end_id))))
#        query_end = datetime.now()
#        cur_id = end_id
#        tot_time = query_end - start_time
#        try:
#            remaining = str(tot_time * ((max_id - cur_id) / (cur_id - min_id)))
#        except OverflowError, e:
#            remaining = '?'
#        print '%.2f%% done, %u matched, %s for query, %s total, ~%s remaining' % ((cur_id * 100.0 / max_id), res.rowcount, query_end - query_start, tot_time, remaining)

#SQL = """
#UPDATE txin SET txout_id = txout.id
#FROM txout JOIN transaction t ON txout.transaction_id = t.id
#WHERE t.tx_hash = txin.previous_output_transaction_hash
#AND txout.transaction_index = txin.previous_output_index AND txin.txout_id IS NULL
#AND txin.previous_output_transaction_hash IN (
#    SELECT tx_hash FROM transaction ORDER BY tx_hash LIMIT %s OFFSET %s
#)
#"""
#
#BLOCK = 1000
#
#def main():
#    max_id = db.session.query(func.max(db.Transaction.id)).scalar()
#    min_id = 0
#    cur_id = min_id
#    start_time = datetime.now()
#    while cur_id <= max_id:
#        end_id = cur_id + BLOCK
#        query_start = datetime.now()
#        with db.engine.begin() as conn:
#            res = conn.execute(SQL, (BLOCK, cur_id))
#        query_end = datetime.now()
#        tot_time = query_end - start_time
#        print '%u - %u / %u %.3f%% done, %u matched, %s for query, %s total, ~%s remaining' % (
#            cur_id,
#            end_id,
#            max_id,
#            (cur_id - min_id) * 100.0 / (max_id - min_id),
#            res.rowcount,
#            query_end - query_start,
#            tot_time,
#            tot_time * int(float(max_id - end_id) / float(end_id - min_id)))
#        cur_id = end_id


# THIS ONE # tx_hash_lookup
#SQL = """
#UPDATE txin SET txout_id = txout.id
#FROM txout JOIN transaction t
#ON txout.transaction_id = t.id
#WHERE t.tx_hash = txin.previous_output_transaction_hash
#AND txout.transaction_index = txin.previous_output_index
#AND txin.txout_id IS NULL
#AND t.id >= %s AND t.id < %s
#"""
#
##SQL = """
##UPDATE txin SET previous_output_transaction_id = t.id
##FROM transaction t
##WHERE t.tx_hash = txin.previous_output_transaction_hash
##AND t.id >= %s AND t.id < %s
##"""
#
#BLOCK = 10000
#
#def main():
#    max_id = db.session.query(func.max(db.Transaction.id)).scalar()
#    min_id = 0  #26322000
#    cur_id = min_id
#    start_time = datetime.now()
#    while cur_id <= max_id:
#        end_id = cur_id + BLOCK
#        query_start = datetime.now()
#        with db.engine.begin() as conn:
#            res = conn.execute(SQL, (cur_id, end_id))
#        query_end = datetime.now()
#        tot_time = query_end - start_time
#        avg_time = tot_time / (end_id - min_id) * BLOCK
#        print '%u - %u / %u %.3f%% done, %u matched, %s for query, %s total, %s avg, ~%s remaining' % (
#            cur_id,
#            end_id,
#            max_id,
#            (cur_id - min_id) * 100.0 / (max_id - min_id),
#            res.rowcount,
#            query_end - query_start,
#            tot_time,
#            avg_time,
#            avg_time * (max_id - end_id) / BLOCK)
#        cur_id = end_id


# THIS ONE # tx_hash_lookup
SQL = """
UPDATE txin SET txout_id = txout.id
FROM txout
JOIN transaction txo ON txout.transaction_id = txo.id
WHERE txo.tx_hash = txin.previous_output_transaction_hash
AND txout.transaction_index = txin.previous_output_index
AND txin.txout_id IS NULL
AND txo.block_id >= %s AND txo.block_id < %s
"""

BLOCK = 1  # 250


class TxInUpdater(object):
    def __init__(self):
        self.max_id = db.session.query(func.max(db.Block.id)).scalar()
        #self.min_id = 11200
#        self.min_id = db.session.query(
#            db.Transaction.block_id
#        ).filter(
#            db.Transaction.id == db.session.query(
#                func.min(db.TxOut.transaction_id)
#            ).join(
#                db.Transaction,
#                db.TxOut.transaction_id == db.Transaction.id
#            ).join(
#                db.TxIn,
#                (db.TxOut.transaction_index == db.TxIn.previous_output_index)
#                & (db.TxIn.previous_output_transaction_hash == db.Transaction.tx_hash)
#            ).filter(
#                db.TxIn.txout_id.is_(None)
#            ).scalar()
#        ).scalar()

        min_txid = db.session.query(
            func.min(db.TxIn.id)
        ).filter(
            db.TxIn.txout_id.is_(None)
            & (db.TxIn.previous_output_transaction_hash != 32 * '\x00')
        ).subquery()
        txin = db.session.query(db.TxIn).filter(db.TxIn.id == min_txid).subquery()
        self.min_id = db.session.query(db.Transaction.block_id).filter(db.Transaction.tx_hash == txin.c.previous_output_transaction_hash).scalar()
        #self.total_to_process = db.session.query(db.TxIn.id).filter(db.TxIn.txout_id.is_(None)).count()
        # takes too long to run
        #self.min_id = db.session.query(
        #    func.min(db.Transaction.block_id)
        #).join(
        #    db.TxOut, db.Transaction.id == db.TxOut.transaction_id
        #).join(
        #    db.TxIn, db.Transaction.tx_hash == db.TxIn.previous_output_transaction_hash
        #).filter(
        #    (db.TxOut.transaction_index == db.TxIn.previous_output_index) & db.TxIn.txout_id.is_(None)
        #).scalar()
        self.start_time = datetime.now()
        self.queue = multiprocessing.Queue()
        self.num_processed = multiprocessing.Value('i', 0)
        self.total_blocks = (self.max_id - self.min_id) / BLOCK
        self.blocks_processed = multiprocessing.Value('i', 0)
        self.shutdown_event = multiprocessing.Event()

    def process_chunk(self, cur_id, end_id):
        query_start = datetime.now()
        with db.engine.begin() as conn:
            res = conn.execute(SQL, (cur_id, end_id))
        query_end = datetime.now()
        tot_time = query_end - self.start_time
        avg_time = tot_time / (end_id - self.min_id) * BLOCK
        with self.num_processed.get_lock():
            self.num_processed.value += res.rowcount
        with self.blocks_processed.get_lock():
            self.blocks_processed.value += 1
        if cur_id % 5 == 0:
            print('%u - %u / %u %.3f%% done, %u matched, %s for query, %s total, %s avg, ~%s remaining' % (
                cur_id,
                end_id,
                self.max_id,
                (cur_id - self.min_id) * 100.0 / (self.max_id - self.min_id),
                res.rowcount,
                query_end - query_start,
                tot_time,
                avg_time,
                avg_time * (self.max_id - end_id) / BLOCK))

    def process_chunks(self):
        while not self.shutdown_event.is_set():
            try:
                args = self.queue.get(timeout=1)
                self.process_chunk(*args)
            except Queue.Empty:
                continue

    def queue_blocks(self):
        cur_id = self.min_id
        while cur_id <= self.max_id:
            end_id = min(cur_id + BLOCK, self.max_id + 1)
            self.queue.put((cur_id, end_id))
            cur_id = end_id

    def run(self):
        self.queue_thread = threading.Thread(target=self.queue_blocks)
        self.queue_thread.start()
        procs = []
        for i in xrange(multiprocessing.cpu_count()):
            proc = multiprocessing.Process(target=self.process_chunks)
            proc.start()
            procs.append(proc)
        output = 0
        while not self.queue.empty():
            with self.blocks_processed.get_lock():
                blocks_processed = self.blocks_processed.value

            tot_time = datetime.now() - self.start_time
            if blocks_processed == 0:
                print('%s' % (tot_time,))
                time.sleep(5)
                continue

            avg_time = tot_time / blocks_processed
            if blocks_processed - output > 20:
                output = blocks_processed
                print('%u / %u %.3f%% done, %s total, %s avg, ~%s remaining\n' % (
                    blocks_processed,
                    self.total_blocks,
                    blocks_processed * 100.0 / self.total_blocks,
                    tot_time,
                    avg_time,
                    avg_time * (self.total_blocks - blocks_processed))
                )
            time.sleep(5)
        self.shutdown_event.set()
        self.queue_thread.join()
        for proc in procs:
            proc.join()


def main():
    TxInUpdater().run()


if __name__ == '__main__':
    main()
