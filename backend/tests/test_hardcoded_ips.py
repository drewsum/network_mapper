import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_hardcoded_ips.py"
spec = importlib.util.spec_from_file_location("check_hardcoded_ips", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def test_flags_private_ip(tmp_path):
    f = tmp_path / "x.py"
    private_ip = ".".join(["10", "1", "2", "3"])  # built at runtime so this file passes the check
    f.write_text(f'PIHOLE = "{private_ip}"\n')
    assert len(checker.violations(f)) == 1


def test_allows_documentation_and_loopback(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('a = "192.0.2.0/24"\nb = "127.0.0.1"\nc = "0.0.0.0"\nv = "version 1.2.3"\n')
    assert checker.violations(f) == []
