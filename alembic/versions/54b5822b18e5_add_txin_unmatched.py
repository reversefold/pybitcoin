"""add txin_unmatched

Revision ID: 54b5822b18e5
Revises: 49789fdd3ed
Create Date: 2015-11-22 14:59:59.060752

"""
from __future__ import print_function

# revision identifiers, used by Alembic.
revision = '54b5822b18e5'
down_revision = '49789fdd3ed'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from datetime import datetime
import logging

from reversefold.util import chunked

from pybitcoin import db


log = logging.getLogger(__name__)

CHUNK_SIZE = 1000


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('txin_unmatched',
        sa.Column('txin_id', sa.Integer(), nullable=False),
        sa.Column('previous_output_transaction_hash', postgresql.BYTEA(length=32), nullable=False),
        sa.Column('previous_output_index', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['txin_id'], ['txin.id'], ),
        sa.PrimaryKeyConstraint('txin_id')
    )

    # INSERT INTO txin_unmatched (txin_id, previous_output_transaction_hash, previous_output_index) SELECT id, previous_output_transaction_hash, previous_output_index FROM txin WHERE txout_id IS NULL
    conn = op.get_bind()
    session = db.Session(bind=conn)
    num_to_insert = session.query(sa.func.count(db.TxIn.id)).filter(db.TxIn.txout_id.is_(None)).scalar()
    print('Going to insert %u records into txin_unmatched' % (num_to_insert,))
    start_time = datetime.now()
    num_inserted = 0
    for chunk in chunked(
        session.query(
            db.TxIn.id, db.TxIn.previous_output_transaction_hash, db.TxIn.previous_output_index
        ).filter(
            db.TxIn.txout_id.is_(None)
        ).yield_per(CHUNK_SIZE),
        chunk_size=CHUNK_SIZE
    ):
        query_start = datetime.now()
        conn.execute(db.TxInUnmatched.__table__.insert().values(chunk))
        query_end = datetime.now()
        num_inserted += len(chunk)
        tot_time = query_end - start_time
        avg_time = tot_time / num_inserted
        print('%u / %u %.3f%% done, %u inserted, %s for query, %s total, %s avg, ~%s remaining' % (
            num_inserted,
            num_to_insert,
            num_inserted * 100.0 / num_to_insert,
            len(chunk),
            query_end - query_start,
            tot_time,
            avg_time,
            avg_time * (num_to_insert - num_inserted)))

    # Create indexes after inserting data
    op.create_index(op.f('ix_txin_unmatched_txin_id'), 'txin_unmatched', ['txin_id'], unique=True)
    op.create_index('ix_txin_unmatched_prev_tx', 'txin_unmatched', ['previous_output_transaction_hash', 'previous_output_index'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_txin_unmatched_txin_id'), table_name='txin_unmatched')
    op.drop_index('ix_txin_unmatched_prev_tx', table_name='txin_unmatched')
    op.drop_table('txin_unmatched')
    ### end Alembic commands ###