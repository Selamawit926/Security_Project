"""empty message

Revision ID: 0ae7a6ec6dfd
Revises: 58069f19df5f
Create Date: 2023-06-20 04:31:39.332839

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0ae7a6ec6dfd'
down_revision = '58069f19df5f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pincode', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('otp_verified', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('otp_verified')
        batch_op.drop_column('pincode')

    # ### end Alembic commands ###
