"""port scan

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-14 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = "'new_device', 'online', 'offline', 'new_ip'"
NEW_KINDS = OLD_KINDS + ", 'port_opened', 'port_closed'"


def upgrade() -> None:
    op.add_column(
        "devices", sa.Column("ports_scanned_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("ports", sa.Column("open", sa.Boolean(), server_default="true", nullable=False))
    op.add_column("device_events", sa.Column("port", sa.Integer(), nullable=True))
    op.add_column("device_events", sa.Column("protocol", sa.Text(), nullable=True))
    op.drop_constraint("ck_device_events_kind", "device_events", type_="check")
    op.create_check_constraint("ck_device_events_kind", "device_events", f"kind IN ({NEW_KINDS})")


def downgrade() -> None:
    op.execute("DELETE FROM device_events WHERE kind IN ('port_opened', 'port_closed')")
    op.drop_constraint("ck_device_events_kind", "device_events", type_="check")
    op.create_check_constraint("ck_device_events_kind", "device_events", f"kind IN ({OLD_KINDS})")
    op.drop_column("device_events", "protocol")
    op.drop_column("device_events", "port")
    op.drop_column("ports", "open")
    op.drop_column("devices", "ports_scanned_at")
