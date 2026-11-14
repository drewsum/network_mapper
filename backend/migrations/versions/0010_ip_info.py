"""ip info (GeoIP) and domain city

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-14 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ip_info",
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("country", sa.Text(), nullable=True),
        sa.Column("city", sa.Text(), nullable=True),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("asn_org", sa.Text(), nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("ip"),
    )
    op.add_column("domains", sa.Column("city", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("domains", "city")
    op.drop_table("ip_info")
