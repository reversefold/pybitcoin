import datetime
import logging

from sqlalchemy import create_engine
from sqlalchemy import Column, BigInteger, Integer, LargeBinary, ForeignKey, String, Sequence, BINARY
from sqlalchemy.schema import Index
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.orderinglist import ordering_list

#from sqlalchemy.dialects.postgresql import BYTEA as BINARY

from pybitcoin import protocol


log = logging.getLogger(__name__)

engine = create_engine('sqlite:///pybitcoin.sqlite')  #, echo=True)
#engine = create_engine('postgresql+psycopg2://127.0.0.1:5432/pybitcoin', connect_args={'user': 'pybitcoin', 'password': 'password'})  #, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


def row_to_dict(row):
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}


class TxIn(Base):
    __tablename__ = 'txin'
    id = Column(Integer, Sequence('txin_id'), primary_key=True, nullable=False, unique=True, index=True)
    previous_output_transaction_hash = Column(BINARY(32), nullable=False, index=True)
    previous_output_index = Column(BigInteger, nullable=False)
    signature_script = Column(LargeBinary, nullable=False)
    sequence = Column(BigInteger, nullable=False)
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)

    __table_args__ = (Index('txin_tx_hash_idx', 'previous_output_transaction_hash', 'previous_output_index'),)

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


class TxOut(Base):
    __tablename__ = 'txout'
    id = Column(Integer, Sequence('txout_id'), primary_key=True, nullable=False, unique=True, index=True)
    value = Column(BigInteger, nullable=False)
    pk_script = Column(LargeBinary, nullable=False)
    to_address = Column(String(34), index=True)  # 27-34 chars
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)
    transaction_index = Column(Integer, nullable=False, index=True)

    __table_args__ = (Index('txout_tx_id_idx', 'transaction_id', 'transaction_index'),)

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


class Transaction(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, Sequence('transaction_id'), primary_key=True, nullable=False, unique=True, index=True)
    tx_hash = Column(BINARY(32), nullable=False, index=True)  #, unique=True?
    version = Column(BigInteger, nullable=False)
    lock_time = Column(Integer, nullable=False)
    tx_inputs = relationship('TxIn')
    tx_outputs = relationship('TxOut', order_by='TxOut.transaction_index',
                              collection_class=ordering_list('transaction_index'))
    block_id = Column(Integer, ForeignKey('block.id'), index=True)
    block = relationship('Block')

    @classmethod
    def from_protocol(cls, in_tx):
        out_tx = cls()
        out_tx.tx_hash = in_tx.tx_hash()
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


class Block(Base):
    __tablename__ = 'block'
    id = Column(Integer, Sequence('block_id'), primary_key=True, nullable=False, unique=True, index=True)
    block_hash = Column(BINARY(32), nullable=False, index=True)  #, unique=True?
    version = Column(BigInteger, nullable=False)
    prev_block_hash = Column(BINARY(32), nullable=False, index=True)
    merkle_root = Column(BINARY(32), nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    bits = Column(BigInteger, nullable=False)
    nonce = Column(BigInteger, nullable=False)
    transactions = relationship('Transaction')

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

    def to_procotol(self):
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


Base.metadata.create_all(engine)

for table in Base.metadata.tables.itervalues():
    for idx in table.indexes:
        try:
            log.debug('Creating %r', idx)
            idx.create(engine)
            log.info('Created %r', idx)
        except Exception as exc:
            log.debug('exc, probably already exists: %r', exc)
