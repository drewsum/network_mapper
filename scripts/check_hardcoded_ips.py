"""Fail if a tracked file contains a hardcoded IP address.

Network-specific values must come from env vars (see backend/src/netmap/config.py).
Allowed: loopback, unspecified (0.0.0.0) and the RFC 5737 / RFC 3849 documentation ranges
used in tests and examples. Usage: python scripts/check_hardcoded_ips.py [files...]
"""

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

SKIP_NAMES = {".env.example", "uv.lock", "package-lock.json"}
SKIP_SUFFIXES = {".png", ".jpg", ".ico", ".svg", ".woff", ".woff2", ".lock"}
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?![\w.])")
ALLOWED = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "0.0.0.0/32", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [Path(p) for p in out.splitlines()]


def violations(path: Path) -> list[str]:
    if path.name in SKIP_NAMES or path.suffix in SKIP_SUFFIXES or not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return []
    found = []
    for lineno, line in enumerate(lines, 1):
        for match in IPV4.finditer(line):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue  # e.g. a version string like 300.1.2.3
            if not any(ip in net for net in ALLOWED):
                found.append(f"{path}:{lineno}: {match.group(0)}")
    return found


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv] if argv else tracked_files()
    found = [v for f in files for v in violations(f)]
    for v in found:
        print(v)
    if found:
        print("hardcoded IPs found; move them to NETMAP_* env settings", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
