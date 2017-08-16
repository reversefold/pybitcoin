#!/usr/bin/env python
from __future__ import print_function
import binascii
from datetime import datetime
import os
from sqlalchemy.orm import aliased
import sys

from pybitcoin import db

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

"""
update block set prev_block_id = p.id from block p where block.prev_block_hash = p.block_hash and block.prev_block_id is null;
update block set depth = p.depth + 1 from block p where block.prev_block_id = p.id and block.depth is null and p.depth is not null;
"""

def main():
    start_time = datetime.now()
    #block_id, block_hash, depth = (0, '\0' * 32, 0)
    #block_id, block_hash, depth = (257339, binascii.unhexlify('610ebdcb90530fe6f5c7911479ce8b257738f048390adb5d102cf91200000000'), 12054)

    db_session = db.Session()

    res = db.engine.execute('update block set prev_block_id = p.id from block p where block.prev_block_hash = p.block_hash and block.prev_block_id is null')
    print('%r prev_block_id set' % (res.rowcount,))
    db_session.commit()

    db_session.query(db.Block).filter(db.Block.prev_block_hash == 32 * '\x00').update(values={'depth': 0})

    ChildBlock = aliased(db.Block, name='child_block')
    ParentBlock = aliased(db.Block, name='parent_block')
    prev = None
    found = True
    while found:
        found = False
        for block_id, block_hash, depth in (
            db_session.query(
                ParentBlock.id, ParentBlock.block_hash, ParentBlock.depth
            ).join(
                ChildBlock, ChildBlock.prev_block_id == ParentBlock.id
            ).filter(
                (ChildBlock.depth.is_(None)) & (ParentBlock.depth.isnot(None))
            )
        ):
            if prev == block_id:
                break
            prev = block_id
            found = True
            while True:
                depth += 1
                res = db_session.query(db.Block.id, db.Block.block_hash).filter(db.Block.prev_block_id == block_id).first()
                if res is None:
                    break
                #prev_block_id = block_id
                block_id, block_hash = res
                db_session.query(db.Block).filter(db.Block.id == block_id).update(values={'depth': depth})  # , 'prev_block_id': prev_block_id})
                #if depth % 20 == 0:
                #    db_session.commit()
                db_session.commit()
                print('%7i %7i %s' % (depth, block_id, binascii.hexlify(block_hash)))
            #db_session.commit()

    # the above worked the last time I tried it but previously I needed the below to update some blocks
    while True:
        res = db.engine.execute('update block set depth = p.depth + 1 from block p where block.prev_block_id = p.id and block.depth is null and p.depth is not null returning block.id, block.depth, block.block_hash')
        if res.rowcount == 0:
            break
        blk_id, depth, blk_hash = res.first()
        print('%i %7i %7i %s' % (res.rowcount, blk_id, depth, binascii.hexlify(blk_hash)))
        db_session.commit()


if __name__ == '__main__':
    main()
