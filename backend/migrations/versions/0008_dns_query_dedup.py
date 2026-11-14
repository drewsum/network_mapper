"""dns query dedup

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-14 16:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _without_compression(orderby: str, change) -> None:
    """TimescaleDB can't add indexes while compression is on: decompress, switch it off,
    make the change, and switch it back on. `netmap migrate` re-adds the policy after."""
    op.execute("SELECT remove_compression_policy('dns_queries', if_exists => true)")
    op.execute(
        "SELECT decompress_chunk(c, if_compressed => true) FROM show_chunks('dns_queries') c"
    )
    op.execute("ALTER TABLE dns_queries SET (timescaledb.compress = false)")
    change()
    op.execute(
        "ALTER TABLE dns_queries SET (timescaledb.compress, "
        f"timescaledb.compress_segmentby = 'mac', timescaledb.compress_orderby = '{orderby}')"
    )


def upgrade() -> None:
    # Unique indexes on a hypertable must include its time column.
    _without_compression(
        "time DESC, pihole_id",
        lambda: op.create_index(
            "uq_dns_queries_pihole",
            "dns_queries",
            ["pihole_id", "time"],
            unique=True,
            postgresql_where=sa.text("pihole_id IS NOT NULL"),
        ),
    )


def downgrade() -> None:
    _without_compression(
        "time DESC", lambda: op.drop_index("uq_dns_queries_pihole", table_name="dns_queries")
    )
