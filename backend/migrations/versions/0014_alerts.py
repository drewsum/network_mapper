"""alert engine: rules, notification state, collector cursors

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-15 03:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = (
    "new_device", "offline", "port_opened", "new_domain", "new_org", "new_country",
    "new_asn", "query_spike", "blocklist_hit", "upnp_forward", "dns_bypass",
)  # fmt: skip


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    # Nothing has written alerts before this revision; start the table clean.
    op.execute("DELETE FROM alerts")
    op.drop_column("alerts", "acknowledged")
    op.add_column("alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True)))
    op.add_column("alerts", sa.Column("dedup_key", sa.Text(), nullable=False))
    op.add_column("alerts", sa.Column("notify", sa.Text()))
    op.add_column("alerts", sa.Column("notified_at", sa.DateTime(timezone=True)))
    op.create_check_constraint("ck_alerts_kind", "alerts", _in("kind", KINDS))
    op.create_check_constraint(
        "ck_alerts_severity", "alerts", _in("severity", ("info", "warning", "critical"))
    )
    op.create_check_constraint(
        "ck_alerts_notify", "alerts", _in("notify", ("pending", "sent", "duplicate", "failed"))
    )
    op.create_index("ix_alerts_dedup_key_time", "alerts", ["dedup_key", "time"])
    op.create_index(
        "ix_alerts_pending", "alerts", ["time"], postgresql_where=sa.text("notify = 'pending'")
    )
    op.create_index(
        "ix_alerts_open", "alerts", ["time"], postgresql_where=sa.text("acknowledged_at IS NULL")
    )

    op.create_table(
        "alert_rules",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("mac", postgresql.MACADDR(), sa.ForeignKey("devices.mac", ondelete="CASCADE")),
        sa.Column("kind", sa.Text()),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("kind", KINDS), name="ck_alert_rules_kind"),
        sa.CheckConstraint(
            _in("action", ("notify", "record", "mute")), name="ck_alert_rules_action"
        ),
        sa.UniqueConstraint(
            "mac", "kind", name="uq_alert_rules", postgresql_nulls_not_distinct=True
        ),
    )
    op.create_table(
        "collector_cursors",
        sa.Column("name", sa.Text(), primary_key=True),
        sa.Column("value", sa.BigInteger(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("collector_cursors")
    op.drop_table("alert_rules")
    op.drop_index("ix_alerts_open", "alerts")
    op.drop_index("ix_alerts_pending", "alerts")
    op.drop_index("ix_alerts_dedup_key_time", "alerts")
    for name in ("ck_alerts_notify", "ck_alerts_severity", "ck_alerts_kind"):
        op.drop_constraint(name, "alerts", type_="check")
    for column in ("notified_at", "notify", "dedup_key", "acknowledged_at"):
        op.drop_column("alerts", column)
    op.add_column(
        "alerts",
        sa.Column("acknowledged", sa.Boolean(), server_default="false", nullable=False),
    )
