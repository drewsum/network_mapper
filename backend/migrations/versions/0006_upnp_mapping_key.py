"""upnp mapping key

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-14 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A router has one mapping per external port and protocol.
    op.create_unique_constraint(
        "uq_upnp_mappings_port", "upnp_mappings", ["external_port", "protocol"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_upnp_mappings_port", "upnp_mappings", type_="unique")
