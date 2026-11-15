"""traffic capture, critical devices, Fingerbank, Wi-Fi clients, packet captures

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-15 06:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = (
    "new_device", "offline", "port_opened", "new_domain", "new_org", "new_country",
    "new_asn", "query_spike", "blocklist_hit", "upnp_forward", "dns_bypass",
)  # fmt: skip
NEW_KINDS = (
    *OLD_KINDS, "critical_offline", "critical_online", "lateral_traffic", "upload_heavy",
    "unencrypted",
)  # fmt: skip
FLOW_BUCKETS = {"flow_activity_1h": "1 hour", "flow_activity_1d": "1 day"}


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _alert_kinds(kinds: Sequence[str]) -> None:
    for table, name in (("alerts", "ck_alerts_kind"), ("alert_rules", "ck_alert_rules_kind")):
        op.drop_constraint(name, table, type_="check")
        op.create_check_constraint(name, table, _in("kind", kinds))


def upgrade() -> None:
    _alert_kinds(NEW_KINDS)
    op.add_column(
        "devices", sa.Column("critical", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("devices", sa.Column("offline_grace_minutes", sa.Integer()))
    op.add_column("devices", sa.Column("fingerbank", postgresql.JSONB(astext_type=sa.Text())))

    # Compressed hypertable: nullable columns without defaults can be added in place.
    op.add_column("flows", sa.Column("outbound", sa.Boolean()))
    op.add_column("flows", sa.Column("source", sa.Text()))

    op.create_table(
        "packet_captures",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "mac",
            postgresql.MACADDR(),
            sa.ForeignKey("devices.mac", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("max_seconds", sa.Integer(), nullable=False),
        sa.Column("max_bytes", sa.BigInteger(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("packets", sa.BigInteger()),
        sa.Column("error", sa.Text()),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            _in("status", ("pending", "running", "done", "stopped", "failed")),
            name="ck_packet_captures_status",
        ),
    )
    op.create_table(
        "wifi_clients",
        sa.Column("mac", postgresql.MACADDR(), primary_key=True),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("ap_name", sa.Text()),
        sa.Column("ap_mac", postgresql.MACADDR()),
        sa.Column("ssid", sa.Text()),
        sa.Column("band", sa.Text()),
        sa.Column("channel", sa.Integer()),
        sa.Column("signal_dbm", sa.Integer()),
        sa.Column("rx_rate_kbps", sa.BigInteger()),
        sa.Column("tx_rate_kbps", sa.BigInteger()),
        sa.Column("connected", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("connected_since", sa.DateTime(timezone=True)),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(_in("source", ("unifi", "openwrt")), name="ck_wifi_clients_source"),
    )

    # Traffic per device over time, for the history explorer and the map.
    with op.get_context().autocommit_block():
        for view, bucket in FLOW_BUCKETS.items():
            op.execute(f"""
                CREATE MATERIALIZED VIEW {view}
                WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
                SELECT time_bucket(INTERVAL '{bucket}', time) AS bucket,
                       mac,
                       sum(bytes_up)::bigint AS bytes_up,
                       sum(bytes_down)::bigint AS bytes_down,
                       sum(packets)::bigint AS packets
                FROM flows
                GROUP BY bucket, mac
                WITH NO DATA
            """)


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for view in FLOW_BUCKETS:
            op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {view}")
    op.drop_table("wifi_clients")
    op.drop_table("packet_captures")
    op.drop_column("flows", "source")
    op.drop_column("flows", "outbound")
    for column in ("fingerbank", "offline_grace_minutes", "critical"):
        op.drop_column("devices", column)
    op.execute(f"DELETE FROM alerts WHERE NOT ({_in('kind', OLD_KINDS)})")
    op.execute(f"DELETE FROM alert_rules WHERE NOT ({_in('kind', OLD_KINDS)})")
    _alert_kinds(OLD_KINDS)
