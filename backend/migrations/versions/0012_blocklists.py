"""domain categories and blocklist matching

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-14 23:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "blocklists",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("entries", sa.Integer(), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )
    op.create_table(
        "blocklist_domains",
        sa.Column("list", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("list", "domain"),
    )
    op.create_table(
        "blocklist_networks",
        sa.Column("list", sa.Text(), nullable=False),
        sa.Column("network", postgresql.CIDR(), nullable=False),
        sa.PrimaryKeyConstraint("list", "network"),
    )
    op.create_index(
        "ix_blocklist_networks_network",
        "blocklist_networks",
        ["network"],
        postgresql_using="gist",
        postgresql_ops={"network": "inet_ops"},
    )
    op.add_column(
        "domains",
        sa.Column("pihole_blocked", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "domains",
        sa.Column("blocklists", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
    )
    op.create_index("ix_domains_category", "domains", ["category"])
    # Whether each domain's most recent query (still in raw retention) was blocked.
    op.execute("""
        UPDATE domains d SET pihole_blocked = true
        FROM (
            SELECT DISTINCT ON (domain) domain, status FROM dns_queries
            ORDER BY domain, time DESC
        ) q
        WHERE q.domain = d.domain AND q.status = 'blocked'
    """)


def downgrade() -> None:
    op.drop_index("ix_domains_category", table_name="domains")
    op.drop_column("domains", "blocklists")
    op.drop_column("domains", "pihole_blocked")
    op.drop_index("ix_blocklist_networks_network", table_name="blocklist_networks")
    op.drop_table("blocklist_networks")
    op.drop_table("blocklist_domains")
    op.drop_table("blocklists")
