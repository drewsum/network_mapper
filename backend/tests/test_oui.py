from netmap import oui

CSV = """Registry,Assignment,Organization Name,Organization Address
MA-L,00AA00,"Example  Corp, Inc.",Somewhere
MA-M,00AA001,Small Block Ltd,"Elsewhere "
MA-L,00BB00,Private,
"""


def test_parse_registry_normalizes_and_skips_private():
    assert list(oui.parse_registry(CSV)) == [
        ("00aa00", "Example Corp, Inc."),
        ("00aa001", "Small Block Ltd"),
    ]


def test_bundle_round_trip(tmp_path):
    path = tmp_path / "oui.tsv.gz"
    entries = {"00aa00": "Example Corp, Inc.", "00aa001": "Small Block Ltd"}
    oui.write_bundle(entries.items(), path)
    assert oui.read_bundle(path) == entries
    first = path.read_bytes()
    oui.write_bundle(reversed(list(entries.items())), path)
    assert path.read_bytes() == first  # deterministic, so unchanged data means no git diff


def test_shipped_bundle_covers_all_block_sizes():
    entries = oui.read_bundle()
    assert entries["b827eb"].startswith("Raspberry Pi")
    assert {len(p) for p in entries} == {6, 7, 9}
