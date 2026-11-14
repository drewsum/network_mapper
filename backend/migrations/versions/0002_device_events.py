"""device events

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-13 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mac", postgresql.MACADDR(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.CheckConstraint(
            "kind IN ('new_device', 'online', 'offline', 'new_ip')",
            name="ck_device_events_kind",
        ),
        sa.ForeignKeyConstraint(["mac"], ["devices.mac"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_device_events_mac_time", "device_events", ["mac", "time"])


def downgrade() -> None:
    op.drop_index("ix_device_events_mac_time", table_name="device_events")
    op.drop_table("device_events")
