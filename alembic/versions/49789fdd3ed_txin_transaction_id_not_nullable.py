"""txin.transaction_id not nullable

Revision ID: 49789fdd3ed
Revises: 444bc3ab78cf
Create Date: 2015-11-22 14:42:13.930086

"""

# revision identifiers, used by Alembic.
revision = '49789fdd3ed'
down_revision = '444bc3ab78cf'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('txin', 'transaction_id',
               existing_type=sa.INTEGER(),
               nullable=False)


def downgrade():
    op.alter_column('txin', 'transaction_id',
               existing_type=sa.INTEGER(),
               nullable=True)
