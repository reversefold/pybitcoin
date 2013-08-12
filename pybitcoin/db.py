from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, BINARY, LargeBinary, ForeignKey, String, Sequence
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from pybitcoin import protocol


engine = create_engine('sqlite:///pybitcoin.sqlite')  #, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


class TxIn(Base):
    __tablename__ = 'txin'
    id = Column(Integer, Sequence('txin_id'), primary_key=True, nullable=False, unique=True, index=True)
    previous_output_transaction_hash = Column(BINARY(32), nullable=False, index=True)
    previous_output_index = Column(Integer, nullable=False)
    signature_script = Column(LargeBinary, nullable=False)
    sequence = Column(Integer, nullable=False)
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)

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


class TxOut(Base):
    __tablename__ = 'txout'
    id = Column(Integer, Sequence('txout_id'), primary_key=True, nullable=False, unique=True, index=True)
    value = Column(Integer, nullable=False)
    pk_script = Column(LargeBinary, nullable=False)
    to_address = Column(String(34), index=True)  # 27-34 chars
    transaction_id = Column(Integer, ForeignKey('transaction.id'), index=True)

    @classmethod
    def from_protocol(cls, in_txout):
        out_txout = cls()
        out_txout.value = in_txout.value
        out_txout.pk_script = in_txout.pk_script.bytes
        out_txout.to_address = in_txout.pk_script.to_address
        return out_txout

    def to_protocol(self):
        return protocol.TxOut(self.value, protocol.PubKeyScript(self.pk_script))


class Transaction(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, Sequence('transaction_id'), primary_key=True, nullable=False, unique=True, index=True)
    tx_hash = Column(BINARY(32), nullable=False, unique=True, index=True)
    version = Column(Integer, nullable=False)
    lock_time = Column(Integer, nullable=False)
    tx_inputs = relationship('TxIn')
    tx_outputs = relationship('TxOut')
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


class Block(Base):
    __tablename__ = 'block'
    id = Column(Integer, Sequence('block_id'), primary_key=True, nullable=False, unique=True, index=True)
    block_hash = Column(BINARY(32), nullable=False, unique=True, index=True)
    version = Column(Integer, nullable=False)
    prev_block_hash = Column(BINARY(32), nullable=False, index=True)
    merkle_root = Column(BINARY(32), nullable=False)
    timestamp = Column(Integer, nullable=False)
    bits = Column(Integer, nullable=False)
    nonce = Column(Integer, nullable=False)
    transactions = relationship('Transaction')

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


Base.metadata.create_all(engine)
