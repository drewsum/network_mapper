"""TimescaleDB retention / compression / refresh policies.

These are driven by settings (env), so they're (re)applied on every `netmap migrate`
instead of being frozen into a migration. All calls are idempotent.
"""

import logging

from sqlalchemy import Connection, text

from netmap.config import Settings

log = logging.getLogger(__name__)

# view -> (refresh start_offset, end_offset, schedule_interval)
CAGG_REFRESH = {
    "dns_activity_1m": ("2 hours", "1 minute", "1 minute"),
    "dns_activity_1h": ("3 days", "1 hour", "15 minutes"),
    "dns_activity_1d": ("7 days", "1 day", "1 hour"),
}


def _days(n: int) -> str:
    return f"{n} days"


def retention_days(settings: Settings) -> dict[str, int]:
    return {
        "dns_queries": settings.raw_retention_days,
        "flows": settings.raw_retention_days,
        "dns_activity_1m": settings.raw_retention_days,
        "dns_activity_1h": settings.agg_1h_retention_days,
        "dns_activity_1d": settings.agg_1d_retention_days,
    }


def apply_policies(conn: Connection, settings: Settings) -> None:
    for hypertable in ("dns_queries", "flows"):
        conn.execute(
            text("SELECT remove_compression_policy(:t, if_exists => true)"), {"t": hypertable}
        )
        conn.execute(
            text("SELECT add_compression_policy(:t, CAST(:after AS interval))"),
            {"t": hypertable, "after": _days(settings.compress_after_days)},
        )

    for view, (start, end, every) in CAGG_REFRESH.items():
        conn.execute(
            text("SELECT remove_continuous_aggregate_policy(:v, if_exists => true)"), {"v": view}
        )
        conn.execute(
            text(
                "SELECT add_continuous_aggregate_policy(:v, "
                "start_offset => CAST(:s AS interval), end_offset => CAST(:e AS interval), "
                "schedule_interval => CAST(:i AS interval))"
            ),
            {"v": view, "s": start, "e": end, "i": every},
        )

    for relation, days in retention_days(settings).items():
        conn.execute(text("SELECT remove_retention_policy(:r, if_exists => true)"), {"r": relation})
        conn.execute(
            text("SELECT add_retention_policy(:r, CAST(:d AS interval))"),
            {"r": relation, "d": _days(days)},
        )
        log.info("retention %s = %d days", relation, days)


def refresh_all_aggregates(conn: Connection) -> None:
    """Materialize the full history (e.g. after seeding). Needs an autocommit connection."""
    for view in CAGG_REFRESH:
        conn.execute(text(f"CALL refresh_continuous_aggregate('{view}', NULL, NULL)"))
