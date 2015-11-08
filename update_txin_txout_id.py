#!/usr/bin/env python
import binascii
from datetime import datetime
import os
from sqlalchemy import func
import sys

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

BLOCK = 1000


def main():
    max_id = db.session.query(func.max(db.Block.id)).scalar()
    # takes too long to run
    #min_id = db.session.query(
    #    func.min(db.Transaction.block_id)
    #).join(
    #    db.TxOut, db.Transaction.id == db.TxOut.transaction_id
    #).join(
    #    db.TxIn, db.Transaction.tx_hash == db.TxIn.previous_output_transaction_hash
    #).filter(
    #    (db.TxOut.transaction_index == db.TxIn.previous_output_index) & db.TxIn.txout_id.is_(None)
    #).scalar()
    min_id = 8900
    cur_id = min_id
    start_time = datetime.now()
    while cur_id <= max_id:
        end_id = min(cur_id + BLOCK, max_id + 1)
        query_start = datetime.now()
        with db.engine.begin() as conn:
            res = conn.execute(SQL, (cur_id, end_id))
        query_end = datetime.now()
        tot_time = query_end - start_time
        avg_time = tot_time / (end_id - min_id) * BLOCK
        print('%u - %u / %u %.3f%% done, %u matched, %s for query, %s total, %s avg, ~%s remaining' % (
            cur_id,
            end_id,
            max_id,
            (cur_id - min_id) * 100.0 / (max_id - min_id),
            res.rowcount,
            query_end - query_start,
            tot_time,
            avg_time,
            avg_time * (max_id - end_id) / BLOCK))
        cur_id = end_id


if __name__ == '__main__':
    main()
