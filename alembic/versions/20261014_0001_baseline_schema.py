"""baseline schema

Schema inicial, idêntico ao que `db.create_all()` criava antes do Alembic. Bancos que já
existiam (produção) não rodam esta migração: scripts/migrate.py confere o schema e os
carimba (`stamp`) nesta revisão.

Revision ID: 0001
Revises: 
Create Date: 2026-10-14 09:57:17.040636

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('tbl_0',
    sa.Column('col_a0', sa.String(length=36), nullable=False),
    sa.Column('col_a1', sa.String(length=500), nullable=False),
    sa.Column('col_a1_hash', sa.String(length=64), nullable=False),
    sa.Column('col_a2', sa.String(length=255), nullable=False),
    sa.Column('col_a3', sa.String(length=500), nullable=False),
    sa.Column('col_a4', sa.Boolean(), nullable=False),
    sa.Column('col_a5', sa.Boolean(), nullable=False),
    sa.Column('col_a6', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('col_a0'),
    sa.UniqueConstraint('col_a1')
    )
    op.create_index(op.f('ix_tbl_0_col_a1_hash'), 'tbl_0', ['col_a1_hash'], unique=True)
    op.create_table('tbl_1',
    sa.Column('col_b0', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('col_b1', sa.String(length=36), nullable=False),
    sa.Column('col_b2', sa.String(length=500), nullable=False),
    sa.Column('col_b2_hash', sa.String(length=64), nullable=False),
    sa.Column('col_b3', sa.String(length=500), nullable=False),
    sa.Column('col_b4', sa.String(length=500), nullable=False),
    sa.Column('col_b4_hash', sa.String(length=64), nullable=False),
    sa.Column('col_b5', sa.Boolean(), nullable=False),
    sa.Column('col_b6', sa.String(length=500), nullable=True),
    sa.Column('col_b7', sa.String(length=500), nullable=True),
    sa.ForeignKeyConstraint(['col_b1'], ['tbl_0.col_a0'], ),
    sa.PrimaryKeyConstraint('col_b0')
    )
    op.create_index(op.f('ix_tbl_1_col_b2_hash'), 'tbl_1', ['col_b2_hash'], unique=False)
    op.create_index(op.f('ix_tbl_1_col_b4_hash'), 'tbl_1', ['col_b4_hash'], unique=False)
    op.create_table('tbl_3',
    sa.Column('col_d0', sa.Integer(), nullable=False),
    sa.Column('col_d1', sa.String(length=50), nullable=False),
    sa.Column('col_d2', sa.String(length=36), nullable=False),
    sa.ForeignKeyConstraint(['col_d2'], ['tbl_0.col_a0'], ),
    sa.PrimaryKeyConstraint('col_d0')
    )
    op.create_table('tbl_2',
    sa.Column('col_c0', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('col_c1', sa.Integer(), nullable=False),
    sa.Column('col_c2', sa.DateTime(), nullable=True),
    sa.Column('col_c3', sa.String(length=500), nullable=True),
    sa.Column('col_c4', sa.String(length=500), nullable=True),
    sa.Column('col_c5', sa.String(length=500), nullable=True),
    sa.Column('col_c6', sa.String(length=500), nullable=True),
    sa.Column('col_c7', sa.String(length=500), nullable=True),
    sa.Column('col_c8', sa.String(length=500), nullable=True),
    sa.Column('col_c9', sa.String(length=500), nullable=True),
    sa.Column('col_c10', sa.String(length=500), nullable=True),
    sa.ForeignKeyConstraint(['col_c1'], ['tbl_1.col_b0'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('col_c0')
    )
    op.create_table('tbl_4',
    sa.Column('col_e0', sa.Integer(), nullable=False),
    sa.Column('col_e1', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['col_e0'], ['tbl_1.col_b0'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['col_e1'], ['tbl_3.col_d0'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('col_e0', 'col_e1')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('tbl_4')
    op.drop_table('tbl_2')
    op.drop_table('tbl_3')
    op.drop_index(op.f('ix_tbl_1_col_b4_hash'), table_name='tbl_1')
    op.drop_index(op.f('ix_tbl_1_col_b2_hash'), table_name='tbl_1')
    op.drop_table('tbl_1')
    op.drop_index(op.f('ix_tbl_0_col_a1_hash'), table_name='tbl_0')
    op.drop_table('tbl_0')
