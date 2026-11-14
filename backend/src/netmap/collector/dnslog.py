"""Domain -> IP answers from Pi-hole's DNS server log (GET /api/logs/dnsmasq).

The query log has no answers, but dnsmasq logs each one: "reply example.com is
203.0.113.34" (or "cached ..." / "cached-stale ..." when served from cache). A name that
is an alias logs "reply www.example.com is <CNAME>" followed by the target's answers,
which then belong to both names. Blocked answers (0.0.0.0, ::) aren't addresses anyone
connects to, and are skipped.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

_ANSWER = re.compile(r"^(?:reply|cached|cached-stale) (\S+) is (\S+)$")


@dataclass(frozen=True)
class Answer:
    domain: str
    ip: str
    time: datetime


def parse_answers(lines: list[dict]) -> list[Answer]:
    """Answers in log lines ({"timestamp", "message"}), oldest first as logged."""
    answers = []
    alias: str | None = None  # the queried name while its CNAME chain is being logged
    for line in lines:
        match = _ANSWER.match(str(line.get("message", "")).strip())
        if not match:
            alias = None
            continue
        name, value = match.group(1).rstrip(".").lower(), match.group(2)
        if value == "<CNAME>":
            alias = alias or name
            continue
        try:
            ip = ip_address(value)
            at = datetime.fromtimestamp(float(line["timestamp"]), UTC)
        except (KeyError, TypeError, ValueError):
            alias = None  # NXDOMAIN, NODATA, <HTTPS> and the like end the chain
            continue
        if ip.is_unspecified:
            continue
        answers.append(Answer(name, str(ip), at))
        if alias and alias != name:
            answers.append(Answer(alias, str(ip), at))
    return answers
