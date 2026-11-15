"""baseline deviations as device events

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-15 02:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = ("new_device", "online", "offline", "new_ip", "port_opened", "port_closed")
NEW_KINDS = (*OLD_KINDS, "new_domain", "new_org", "new_country", "new_asn", "query_spike")


def _kinds(kinds: tuple[str, ...]) -> str:
    return "kind IN (" + ", ".join(f"'{k}'" for k in kinds) + ")"


def upgrade() -> None:
    op.add_column("device_events", sa.Column("details", postgresql.JSONB(astext_type=sa.Text())))
    op.drop_constraint("ck_device_events_kind", "device_events", type_="check")
    op.create_check_constraint("ck_device_events_kind", "device_events", _kinds(NEW_KINDS))
    op.create_check_constraint(
        "ck_device_baselines_key_type",
        "device_baselines",
        "key_type IN ('domain', 'org', 'country', 'asn')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_device_baselines_key_type", "device_baselines", type_="check")
    op.execute(f"DELETE FROM device_events WHERE NOT ({_kinds(OLD_KINDS)})")
    op.drop_constraint("ck_device_events_kind", "device_events", type_="check")
    op.create_check_constraint("ck_device_events_kind", "device_events", _kinds(OLD_KINDS))
    op.drop_column("device_events", "details")
