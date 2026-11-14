"""Domain -> IP answers from Pi-hole's dnsmasq log lines."""

from netmap.collector.dnslog import Answer, parse_answers

T = 1767225600.0


def lines(*messages):
    return [{"timestamp": T + i, "message": m, "prio": None} for i, m in enumerate(messages)]


def pairs(answers: list[Answer]):
    return [(a.domain, a.ip) for a in answers]


def test_replies_and_cached_answers():
    got = parse_answers(
        lines(
            "query[A] example.com from 192.0.2.10",
            "forwarded example.com to 192.0.2.53",
            "reply example.com is 198.51.100.7",
            "cached Example.COM is 198.51.100.7",
            "cached-stale other.example is 2001:db8::5",
        )
    )
    assert pairs(got) == [
        ("example.com", "198.51.100.7"),
        ("example.com", "198.51.100.7"),
        ("other.example", "2001:db8::5"),
    ]
    assert got[0].time.timestamp() == T + 2


def test_cname_chains_credit_the_queried_name():
    got = parse_answers(
        lines(
            "query[A] www.shop.example from 192.0.2.10",
            "reply www.shop.example is <CNAME>",
            "reply shop.cdn.example is <CNAME>",
            "reply edge.cdn.example is 203.0.113.1",
            "reply edge.cdn.example is 203.0.113.2",
            "query[A] next.example from 192.0.2.10",
            "reply next.example is 203.0.113.9",
        )
    )
    assert pairs(got) == [
        ("edge.cdn.example", "203.0.113.1"),
        ("www.shop.example", "203.0.113.1"),
        ("edge.cdn.example", "203.0.113.2"),
        ("www.shop.example", "203.0.113.2"),
        ("next.example", "203.0.113.9"),  # the chain ended with the next query
    ]


def test_blocked_and_empty_answers_are_skipped():
    no_timestamp = {"message": "reply broken.example is 198.51.100.1"}
    got = parse_answers(
        [
            *lines(
                "gravity blocked ads.example is 0.0.0.0",
                "reply ads2.example is 0.0.0.0",
                "reply ads2.example is ::",
                "reply gone.example is NXDOMAIN",
                "reply v4only.example is NODATA-IPv6",
                "reply svc.example is <HTTPS>",
                "config pi.hole is 192.0.2.53",
            ),
            no_timestamp,
        ]
    )
    assert got == []
