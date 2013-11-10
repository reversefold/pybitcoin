#import contextlib
#import shelve
#
#
#@contextlib.contextmanager
#def open_db():
#    db = shelve.open('pybitcoin')
#    try:
#        yield DB(db)
#    finally:
#        db.close()
#
#
#class DB(object):
#    def __init__(self, shelf):
#        self.shelf = shelf
#
#    def get_block(self, block_hash):
#        return self.shelf.get('bk_%s' % (block_hash,))
#
#    def put_block(self, block):
#        block_hash = block.block_hash()
#        self.shelf['bk_%s' % (block_hash,)] = block
#        for txn in block.txns:
#            self.shelf['tx_bk_%s' % (txn.tx_hash,)] = block_hash
#            self.put_tx(txn)
#
#    def get_transaction(self, txn_hash):
#        return self.shelf.get('tx_%s' % (txn_hash,))
#
#    def put_transaction(self, txn):
#        txn_hash = txn.tx_hash
#        self.shelf['tx_%s' % (txn_hash,)] = txn
#        # I'm not sure what the best way to do this is as the list of transactions an address
#        # can be used in are potentially unbounded. Might want to do some kind of limited list
#        # with a pointer to the next list.
#        #
#        # This is where we need a real DB. :-(
#        #for txin in txn.tx_in:
#        #    # store lookup for address to txn_hash
#        #    pass
#        #for txout in txn.tx_out:
#        #    # store lookup for address to txn_hash
#        #    pass
