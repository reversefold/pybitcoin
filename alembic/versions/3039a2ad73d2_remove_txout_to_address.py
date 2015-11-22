"""remove txout.to_address

Revision ID: 3039a2ad73d2
Revises: 3865c2e60350
Create Date: 2015-11-22 15:31:54.112041

"""

# revision identifiers, used by Alembic.
revision = '3039a2ad73d2'
down_revision = '3865c2e60350'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_ixout_to_address_not_spent', table_name='txout')
    op.drop_index('ix_txout_to_address', table_name='txout')
    op.drop_column('txout', 'to_address')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('txout', sa.Column('to_address', sa.VARCHAR(length=34), autoincrement=False, nullable=True))
    op.create_index('ix_txout_to_address', 'txout', ['to_address'], unique=False)
    op.create_index('ix_ixout_to_address_not_spent', 'txout', ['to_address'], unique=False)
    ### end Alembic commands ###