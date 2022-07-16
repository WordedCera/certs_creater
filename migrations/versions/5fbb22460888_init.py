"""Init

Revision ID: 5fbb22460888
Revises: 
Create Date: 2022-06-27 15:57:12.118426

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5fbb22460888'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ops_group',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('name', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tasks',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('status', sa.Boolean(), nullable=True),
    sa.Column('task_id', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('server_mon',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('hostname', sa.Text(), nullable=True),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('ops_group_id', sa.Integer(), nullable=True),
    sa.Column('service', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['ops_group_id'], ['ops_group.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password', sa.Text(), nullable=True),
    sa.Column('name', sa.String(length=80), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('ops_group_id', sa.Integer(), nullable=True),
    sa.Column('role', sa.String(length=10), nullable=True),
    sa.ForeignKeyConstraint(['ops_group_id'], ['ops_group.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('audit',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.Column('scenario', sa.Text(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('actions', sa.Text(), nullable=True),
    sa.Column('outcome', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('certs',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('name', sa.TEXT(), nullable=True),
    sa.Column('csr', sa.TEXT(), nullable=True),
    sa.Column('key', sa.TEXT(), nullable=True),
    sa.Column('pem', sa.TEXT(), nullable=True),
    sa.Column('auth_attr', sa.TEXT(), nullable=True),
    sa.Column('email_specified', sa.TEXT(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('key_storage', sa.Boolean(), nullable=True),
    sa.Column('tasks_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['tasks_id'], ['tasks.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('cert_guts',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('certs_id', sa.INTEGER(), nullable=True),
    sa.Column('cn', sa.TEXT(), nullable=True),
    sa.Column('creation_date', sa.DateTime(), nullable=True),
    sa.Column('exp_date', sa.DateTime(), nullable=True),
    sa.Column('alt_names', sa.TEXT(), nullable=True),
    sa.ForeignKeyConstraint(['certs_id'], ['certs.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('certs_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('cert_guts')
    op.drop_table('certs')
    op.drop_table('audit')
    op.drop_table('users')
    op.drop_table('server_mon')
    op.drop_table('tasks')
    op.drop_table('ops_group')
    # ### end Alembic commands ###
