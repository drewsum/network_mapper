"""organization rules added in the app

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-14 22:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_rules",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("organization", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("kind IN ('suffix', 'asn')", name="ck_org_rules_kind"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "value"),
    )
    op.create_index("ix_domains_organization", "domains", ["organization"])


def downgrade() -> None:
    op.drop_index("ix_domains_organization", table_name="domains")
    op.drop_table("org_rules")
