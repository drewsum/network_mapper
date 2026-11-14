"""device names

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-14 08:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device_names",
        sa.Column("mac", postgresql.MACADDR(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(
            "source IN ('dhcp', 'mdns', 'ssdp', 'netbios', 'rdns')", name="ck_device_names_source"
        ),
        sa.ForeignKeyConstraint(["mac"], ["devices.mac"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("mac", "source"),
    )


def downgrade() -> None:
    op.drop_table("device_names")
