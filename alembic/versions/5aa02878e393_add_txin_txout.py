"""add txin_txout

Revision ID: 5aa02878e393
Revises: 3039a2ad73d2
Create Date: 2015-11-22 15:12:01.133965

"""
from __future__ import print_function
from __future__ import division

# revision identifiers, used by Alembic.
from past.utils import old_div
revision = '5aa02878e393'
down_revision = '3039a2ad73d2'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

from datetime import datetime
import logging

from reversefold.util import chunked

from pybitcoin import db


log = logging.getLogger(__name__)

CHUNK_SIZE = 1000


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('txin_txout',
        sa.Column('txin_id', sa.Integer(), nullable=False),
        sa.Column('txout_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['txin_id'], ['txin.id'], ),
        sa.ForeignKeyConstraint(['txout_id'], ['txout.id'], ),
        sa.PrimaryKeyConstraint('txin_id', 'txout_id')
    )

    # INSERT INTO txin_txout (txin_id, txout_id) SELECT id, txout_id FROM txin WHERE txout_id IS NOT NULL
    conn = op.get_bind()
    session = db.Session(bind=conn)
    num_to_insert = session.query(sa.func.count(db.TxIn.id)).filter(db.TxIn.txout_id.isnot(None)).scalar()
    print('Going to insert %u records into txin_txout' % (num_to_insert,))
    start_time = datetime.now()
    num_inserted = 0
    for chunk in chunked(
        session.query(
            db.TxIn.id, db.TxIn.txout_id
        ).filter(
            db.TxIn.txout_id.isnot(None)
        ).yield_per(CHUNK_SIZE),
        chunk_size=CHUNK_SIZE
    ):
        query_start = datetime.now()
        conn.execute(db.TxIn_TxOut.__table__.insert().values(chunk))
        query_end = datetime.now()
        num_inserted += len(chunk)
        tot_time = query_end - start_time
        avg_time = old_div(tot_time, num_inserted)
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
    op.create_index(op.f('ix_txin_txout_txin_id'), 'txin_txout', ['txin_id'], unique=False)
    op.create_index('ix_txin_txout_txin_id_txout_id', 'txin_txout', ['txin_id', 'txout_id'], unique=True)
    op.create_index(op.f('ix_txin_txout_txout_id'), 'txin_txout', ['txout_id'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_txin_txout_txout_id'), table_name='txin_txout')
    op.drop_index('ix_txin_txout_txin_id_txout_id', table_name='txin_txout')
    op.drop_index(op.f('ix_txin_txout_txin_id'), table_name='txin_txout')
    op.drop_table('txin_txout')
    ### end Alembic commands ###
