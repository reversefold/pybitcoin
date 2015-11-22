import binascii
import datetime
import logging

from sqlalchemy import Column, ForeignKey, Sequence
from sqlalchemy.schema import Index
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy.sql import text
from sqlalchemy.types import Boolean, BigInteger, Integer, LargeBinary, String

from pybitcoin import protocol

try:
    from .db_local import BINARY, engine_factory
except ImportError:
    print 'Using default sqlite DB, create db_local.py to customize'
    from .db_sqlite import BINARY, engine_factory

log = logging.getLogger(__name__)

Base = declarative_base()
engine = None
Session = None


def reconnect():
    global engine, Session
    if engine is not None:
        engine.dispose()
    engine = engine_factory()
    Session = sessionmaker(bind=engine)


reconnect()


def row_to_dict(row):
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}


class TxIn(Base):
    __tablename__ = 'txin'
    id = Column(Integer, Sequence('txin_id'), primary_key=True, nullable=False, unique=True, index=True)
    previous_output_transaction_hash = Column(BINARY(32), nullable=False)
    previous_output_index = Column(BigInteger, nullable=False)
    signature_script = Column(LargeBinary, nullable=False)
    sequence = Column(BigInteger, nullable=False)
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)
    transaction_index = Column(Integer, nullable=False)

    txout_id = Column(Integer, nullable=True, index=True)  # ForeignKey('txout.id'),

    __table_args__ = (
        Index(
            'ix_txin_tx_hash_idx',
            previous_output_transaction_hash, previous_output_index,
            postgresql_where=txout_id.is_(None)
        ),
    )

    @classmethod
    def from_protocol(cls, in_txin):
        out_txin = cls()
        out_txin.previous_output_transaction_hash = in_txin.previous_output[0]
        out_txin.previous_output_index = in_txin.previous_output[1]
        out_txin.signature_script = in_txin.signature_script
        out_txin.sequence = in_txin.sequence
        return out_txin

    def to_protocol(self):
        return protocol.TxIn(
            (self.previous_output_transaction_hash, self.previous_output_index),
            self.signature_script,
            self.sequence)

    @classmethod
    def copy_obj(cls, obj):
        ret = cls()
        ret.id = obj.id
        ret.previous_output_transaction_hash = obj.previous_output_transaction_hash
        ret.previous_output_index = obj.previous_output_index
        ret.signature_script = obj.signature_script
        ret.sequence = obj.sequence
        ret.transaction_id = obj.transaction_id
        return ret

    def __repr__(self):
        return 'TxIn((%s, %r), %s, %r)' % (
            binascii.hexlify(self.previous_output_transaction_hash), self.previous_output_index,
            binascii.hexlify(self.signature_script),
            self.sequence)


class TxOut(Base):
    __tablename__ = 'txout'
    id = Column(Integer, Sequence('txout_id'), primary_key=True, nullable=False, unique=True, index=True)
    value = Column(BigInteger, nullable=False)
    pk_script = Column(LargeBinary, nullable=False)
    to_address = Column(String(34), index=True)  # 27-34 chars
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)
    transaction_index = Column(Integer, nullable=False, index=True)

    __table_args__ = (
        Index('ix_txout_tx_id_idx', transaction_id, transaction_index),
    )

    @classmethod
    def from_protocol(cls, in_txout):
        out_txout = cls()
        out_txout.value = in_txout.value
        out_txout.pk_script = in_txout.pk_script.bytes
        out_txout.to_address = in_txout.pk_script.to_address
        return out_txout

    def to_protocol(self):
        return protocol.TxOut(self.value, protocol.PubKeyScript(self.pk_script))

    @classmethod
    def copy_obj(cls, obj):
        ret = cls()
        ret.id = obj.id
        ret.value = obj.value
        ret.pk_script = obj.pk_script
        ret.to_address = obj.to_address
        ret.transaction_id = obj.transaction_id
        return ret

    def __repr__(self):
        return 'TxOut(%r, %r)' % (self.value, self.pk_script)


class Transaction(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, Sequence('transaction_id'), primary_key=True, nullable=False, unique=True, index=True)
    tx_hash = Column(BINARY(32), nullable=False)  # , unique=True?
    version = Column(BigInteger, nullable=False)
    lock_time = Column(BigInteger, nullable=False)
    tx_inputs = relationship('TxIn', order_by='TxIn.transaction_index',
                             collection_class=ordering_list('transaction_index'))
    tx_outputs = relationship('TxOut', order_by='TxOut.transaction_index',
                              collection_class=ordering_list('transaction_index'))
    block_id = Column(Integer, ForeignKey('block.id'), index=True)
    block_index = Column(Integer, nullable=False)
#    block = relationship('Block')

    __table_args__ = (
        Index(
            'ix_transaction_tx_hash',
            tx_hash,
            # We only ever do == against tx_hash so a hash index will be more efficient
            postgresql_using='hash',
        ),
    )

    @classmethod
    def from_protocol(cls, in_tx):
        out_tx = cls()
        out_tx.tx_hash = in_tx.tx_hash
        out_tx.version = in_tx.version
        out_tx.lock_time = in_tx.lock_time
        out_tx.tx_inputs = [
            TxIn.from_protocol(txin)
            for txin in in_tx.tx_in]
        out_tx.tx_outputs = [
            TxOut.from_protocol(txout)
            for txout in in_tx.tx_out]
        return out_tx

    def to_protocol(self):
        return protocol.Transaction(
            self.version,
            [txin.to_protocol() for txin in self.tx_inputs],
            [txout.to_protocol() for txout in self.tx_outputs],
            self.lock_time)

    @classmethod
    def copy_obj(cls, obj):
        ret = cls()
        ret.id = obj.id
        ret.tx_hash = obj.tx_hash
        ret.version = obj.version
        ret.lock_time = obj.lock_time
        ret.tx_inputs = [TxIn.copy_obj(txin) for txin in obj.tx_inputs]
        ret.tx_outputs = [TxOut.copy_obj(txout) for txout in obj.tx_outputs]
        ret.block_id = obj.block_id
        return ret

    def __repr__(self):
        return 'Transaction(%s, %r, [%s], [%s], %r)' % (
            binascii.hexlify(self.tx_hash),
            self.version,
            ', '.join(repr(tx) for tx in self.tx_inputs),
            ', '.join(repr(tx) for tx in self.tx_outputs),
            self.lock_time)


class Block(Base):
    __tablename__ = 'block'
    id = Column(Integer, Sequence('block_id'), primary_key=True, nullable=False, unique=True, index=True)
    block_hash = Column(BINARY(32), nullable=False, index=True)  # , unique=True?
    version = Column(BigInteger, nullable=False)
    prev_block_hash = Column(BINARY(32), nullable=False)
    merkle_root = Column(BINARY(32), nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    bits = Column(BigInteger, nullable=False)
    nonce = Column(BigInteger, nullable=False)
    transactions = relationship('Transaction', order_by='Transaction.block_index',
                                collection_class=ordering_list('block_index'))

    prev_block_id = Column(Integer, nullable=True, index=True)
    depth = Column(Integer, nullable=True)

    __table_args__ = (
        Index(
            'ix_block_prev_block_hash',
            prev_block_hash,
            postgresql_where=prev_block_id.is_(None)
        ),
    )

    pending_meta_updates = []

    def bulk_insert(self, session):
        conn = session.connection()
        data = row_to_dict(self)
        data.pop('id')
        ret = conn.execute(self.__table__.insert().values(data))
        self.id = ret.inserted_primary_key[0]
        start = datetime.datetime.now()
        data = []
        for txn in self.transactions:
            txn.block_id = self.id
            (txn.id,) = session.execute(txn.__table__.columns['id'].default.next_value()).fetchone()
            row = row_to_dict(txn)
            data.append(row)
        conn.execute(txn.__table__.insert().values(data))
        log.info('Processing transactions took %s', datetime.datetime.now() - start)
        start = datetime.datetime.now()
        data = []
        for txn in self.transactions:
            for txin in txn.tx_inputs:
                txin.transaction_id = txn.id
                row = row_to_dict(txin)
                row.pop('id')
                data.append(row)
        conn.execute(txin.__table__.insert().values(data))
        log.info('Processing txins took %s', datetime.datetime.now() - start)
        start = datetime.datetime.now()
        data = []
        for txn in self.transactions:
            for txout in txn.tx_outputs:
                txout.transaction_id = txn.id
                row = row_to_dict(txout)
                row.pop('id')
                data.append(row)
        conn.execute(txout.__table__.insert().values(data))
        log.info('Processing txouts took %s', datetime.datetime.now() - start)

    def update_chain_metadata(self, session, _update_pending=True):
        # TODO: This needs to be rewritten to keep an index of blocks not in the known block chain and properly choose the right ones when updating pending metadata
        # TODO: update IOLoop.max_height
        res = session.query(Block.depth, Block.id).filter(Block.block_hash == self.prev_block_hash).first()
        if res is None:
            log.warn('Previous block not found, queueing metadata update (%s)', binascii.hexlify(self.block_hash))
            self.pending_meta_updates.append(self)
            return False
        else:
            depth, self.prev_block_id = res
            self.depth = depth + 1 if depth is not None else None
            session.query(Block).filter(Block.id == self.id).update(
                values={'depth': self.depth, 'prev_block_id': self.prev_block_id})
            session.commit()

            if self.depth is None:
                log.warn('Previous block found but depth is null, queueing metadata update (%s)', binascii.hexlify(self.block_hash))
                self.pending_meta_updates.append(self)
                return False

            if _update_pending and self.pending_meta_updates:
                success = True
                while success:
                    success = False

                    for to_update in self.pending_meta_updates[:]:
                        log.info('Running pending meta update for %s', binascii.hexlify(to_update.block_hash))
                        if to_update.update_chain_metadata(session, _update_pending=False):
                            success = True
                            log.info('Pending metadata update succeeded for %s', binascii.hexlify(to_update.block_hash))
                            self.pending_meta_updates.remove(to_update)
                        else:
                            log.error('Pending metadata update failed for %s', binascii.hexlify(to_update.block_hash))
            return True

    def update_metadata(self, session, _update_pending=True):
        with engine.begin() as conn:
            log.info('Updating links from txin to txout in this block')
            start = datetime.datetime.now()
            # match up previously committed txins to newly committed txouts
            # (blocks committed out of order)
            res = conn.execute(
                text("""
                    UPDATE txin SET txout_id = txout.id
                    FROM txout
                    JOIN transaction txo ON txout.transaction_id = txo.id
                    WHERE txo.tx_hash = txin.previous_output_transaction_hash
                    AND txout.transaction_index = txin.previous_output_index
                    AND txin.txout_id IS NULL
                    AND txo.block_id = :block_id
                """),
                block_id=self.id
            )
            log.info('...%i rows, %s', res.rowcount, datetime.datetime.now() - start)
            log.info('Updating links from txin in this block to txout')
            # match up new txins to the txouts in previous transactions
            # (blocks committed in order)
            start = datetime.datetime.now()
            res = conn.execute(
                text("""
                    UPDATE txin SET txout_id = txout.id
                    FROM txout
                    JOIN transaction txo ON txout.transaction_id = txo.id
                    , transaction txi
                    WHERE txo.tx_hash = txin.previous_output_transaction_hash
                    AND txout.transaction_index = txin.previous_output_index
                    AND txin.txout_id IS NULL
                    AND txin.transaction_id = txi.id
                    AND txi.block_id = :block_id
                """),
                block_id=self.id
            )
            log.info('...%i rows, %s', res.rowcount, datetime.datetime.now() - start)
        return self.update_chain_metadata(session)

        #These don't work as expected...:-(
        #(db.session.query(db.TxIn)
        # .select_from(db.TxOut)
        # .join(db.Transaction, db.TxOut.transaction_id == db.Transaction.id)
        # .filter(
        #     (db.Transaction.tx_hash == db.TxIn.previous_output_transaction_hash)
        #     & (db.TxOut.transaction_index == db.TxIn.previous_output_index)
        #     & (db.TxIn.txout_id == None)
        #     & (db.Transaction.block_id == db_block.id))
        # .update(values={'txout_id': db.TxOut.id}, synchronize_session=False)
        #)
        #(db.session.query(db.TxIn)
        # .select_from(db.TxOut)
        # .join(db.Transaction, db.TxOut.transaction_id == db.Transaction.id)
        # .filter(
        #     (db.Transaction.tx_hash == db.TxIn.previous_output_transaction_hash)
        #     & (db.TxOut.transaction_index == db.TxIn.previous_output_index)
        #     & (db.TxIn.txout_id == None)
        #     & (db.TxIn.transaction_id.in_(
        #         db.session.query(db.Transaction.id).filter(db.Block.id == db_block.id))))
        # .update(values={'txout_id': db.TxOut.id}, synchronize_session=False)
        #)

    @classmethod
    def from_protocol(cls, block):
        out_block = cls()
        out_block.block_hash = block.block_hash
        out_block.version = block.version
        out_block.prev_block_hash = block.prev_block_hash
        out_block.merkle_root = block.merkle_root
        out_block.timestamp = block.timestamp
        out_block.bits = block.bits
        out_block.nonce = block.nonce
        out_block.transactions = [
            Transaction.from_protocol(tx) for tx in block.txns]
        return out_block

    def to_protocol(self):
        return protocol.Block(
            self.version, self.prev_block_hash, self.merkle_root, self.timestamp,
            self.bits, self.nonce, [tx.to_protocol() for tx in self.transactions])

    @classmethod
    def copy_obj(cls, obj):
        ret = cls()
        ret.id = obj.id
        ret.block_hash = obj.block_hash
        ret.version = obj.version
        ret.prev_block_hash = obj.prev_block_hash
        ret.merkle_root = obj.merkle_root
        ret.timestamp = obj.timestamp
        ret.bits = obj.bits
        ret.nonce = obj.nonce
        ret.transactions = [Transaction.copy_obj(tx) for tx in obj.transactions]
        return ret

    def __repr__(self):
        return 'Block(%r, %s, %s, %r, %r, %r, %r)' % (
            self.version,
            binascii.hexlify(self.prev_block_hash),
            binascii.hexlify(self.merkle_root),
            self.timestamp,
            self.bits,
            self.nonce,
            self.transactions)


#Base.metadata.create_all(engine)
#
#for table in Base.metadata.tables.itervalues():
#    for idx in table.indexes:
#        try:
#            log.info('Creating %r', idx)
#            idx.create(engine)
#            log.info('Created %r', idx)
#        except Exception as exc:
#            log.info('exc, probably already exists: %r', exc)
#import sys; sys.exit()


# unspent sum for an address
#  select sum(value) from txout join transaction t on txout.transaction_id = t.id left join txin on txout.transaction_index = txin.previous_output_index and t.tx_hash = txin.previous_output_transaction_hash where txout.to_address = '1ADDRESS' and txin.id is null;
