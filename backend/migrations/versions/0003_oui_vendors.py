"""oui vendors

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-14 06:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oui_vendors",
        sa.Column("prefix", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("prefix"),
    )


def downgrade() -> None:
    op.drop_table("oui_vendors")
