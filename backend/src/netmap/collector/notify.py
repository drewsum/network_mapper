"""Sends alerts out through Apprise (NETMAP_APPRISE_URLS): ntfy, Discord, email, and the
other services Apprise knows (github.com/caronc/apprise/wiki).

Each round sends at most one notification, covering every alert waiting since the last.
An alert repeating one notified in the last hour (the same dedup key) isn't sent again; at
most NETMAP_NOTIFY_MAX_PER_HOUR notifications go out an hour, and alerts past that wait
and go out together. A failed send is retried; alerts still unsent after a day are given
up on.
"""

from datetime import datetime, timedelta

import apprise
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netmap.db.models import Alert

# The health check that reports delivery problems.
CHECK = "notifications"
DEDUP_WINDOW = timedelta(hours=1)
GIVE_UP = timedelta(days=1)
# Alerts listed in one notification; the rest are counted.
MAX_LINES = 10
SEVERITY_ORDER = ("info", "warning", "critical")
NOTIFY_TYPES = {
    "info": apprise.NotifyType.INFO,
    "warning": apprise.NotifyType.WARNING,
    "critical": apprise.NotifyType.FAILURE,
}


class NotifyError(Exception):
    pass


class Notifier:
    """Apprise, loaded with NETMAP_APPRISE_URLS."""

    def __init__(self, urls: str, public_url: str | None = None) -> None:
        self.apprise = apprise.Apprise()
        self.apprise.add(urls)
        self.link = f"{public_url.rstrip('/')}/#/alerts" if public_url else None

    @property
    def services(self) -> int:
        return len(self.apprise)

    def send(self, title: str, body: str, severity: str = "info") -> None:
        if not self.services:
            raise NotifyError("none of NETMAP_APPRISE_URLS is a URL Apprise understands")
        if self.link:
            body = f"{body}\n\n{self.link}"
        if not self.apprise.notify(title=title, body=body, notify_type=NOTIFY_TYPES[severity]):
            raise NotifyError(f"Apprise couldn't deliver to every one of {self.services} services")


def compose(alerts: list[Alert], labels: dict[str, str]) -> tuple[str, str, str]:
    """Title, body and severity of one notification for ``alerts``."""
    severity = max((a.severity for a in alerts), key=SEVERITY_ORDER.index)
    if len(alerts) == 1:
        return f"netmap: {labels.get(alerts[0].kind, alerts[0].kind)}", alerts[0].message, severity
    lines = [f"• {a.message}" for a in alerts[:MAX_LINES]]
    if len(alerts) > MAX_LINES:
        lines.append(f"…and {len(alerts) - MAX_LINES} more")
    return f"netmap: {len(alerts)} alerts", "\n".join(lines), severity


def send_pending(
    session: Session, now: datetime, notifier: Notifier, max_per_hour: int, labels: dict[str, str]
) -> int:
    """Send the alerts waiting to go out, in one notification; ``labels`` names the alert
    kinds. Commits. Returns how many were sent; raises NotifyError (or anything Apprise
    raises) if sending failed."""
    pending = session.scalars(
        select(Alert).where(Alert.notify == "pending").order_by(Alert.time, Alert.id)
    ).all()
    if not pending:
        return 0
    batch: list[Alert] = []
    repeats: list[Alert] = []
    recent = set(
        session.scalars(
            select(Alert.dedup_key).where(
                Alert.dedup_key.in_({a.dedup_key for a in pending}),
                Alert.notify == "sent",
                Alert.notified_at >= now - DEDUP_WINDOW,
            )
        )
    )
    for a in pending:
        if a.time < now - GIVE_UP:
            a.notify, a.notified_at = "failed", now
        elif a.dedup_key in recent:
            a.notify, a.notified_at = "duplicate", now
        elif any(b.dedup_key == a.dedup_key for b in batch):
            repeats.append(a)
        else:
            batch.append(a)
    sent_lately = session.scalar(
        select(func.count(func.distinct(Alert.notified_at))).where(
            Alert.notify == "sent", Alert.notified_at >= now - timedelta(hours=1)
        )
    )
    if not batch or sent_lately >= max_per_hour:
        session.commit()
        return 0
    try:
        notifier.send(*compose(batch, labels))
    except Exception:
        session.commit()  # the repeats and give-ups still count
        raise
    for a in batch:
        a.notify, a.notified_at = "sent", now
    for a in repeats:
        a.notify, a.notified_at = "duplicate", now
    session.commit()
    return len(batch)
