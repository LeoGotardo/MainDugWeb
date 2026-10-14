"""credential domain

Domínio da credencial para o preenchimento automático (`Passwords.domain`, cifrado). Só a
coluna: o valor é cifrado com ENCRYPTION_KEY, que o job de migração não tem. Credenciais sem
domínio continuam usando o site normalizado (feito na leitura, na app e na extensão).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-14 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: Union[str, Sequence[str], None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('tbl_1') as batch_op:
        batch_op.add_column(sa.Column('col_b8', sa.String(length=500), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('tbl_1') as batch_op:
        batch_op.drop_column('col_b8')
