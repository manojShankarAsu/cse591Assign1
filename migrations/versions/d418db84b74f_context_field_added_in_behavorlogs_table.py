"""context field added in behavorlogs table

Revision ID: d418db84b74f
Revises: d73f4484c441
Create Date: 2018-09-19 21:26:10.377693

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd418db84b74f'
down_revision = 'd73f4484c441'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('behavior_logs', sa.Column('context', sa.String(length=140), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('behavior_logs', 'context')
    # ### end Alembic commands ###
