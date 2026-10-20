import hashlib

import pytest

from storozh.signatures import SignatureDB, SignatureError, compile_hex, eicar_bytes, load_default


def test_eicar_constant_is_the_official_test_file():
    data = eicar_bytes()
    assert len(data) == 68
    assert hashlib.md5(data).hexdigest() == "44d88612fea8a8f36de82e1278abb02f"


def test_default_db_contains_eicar_hashes_and_pattern():
    db = load_default()
    digest = hashlib.sha256(eicar_bytes()).hexdigest()
    assert db.hashes["sha256"][digest] == "EICAR-Test-File"
    assert any(p.name == "EICAR-Test-File.Embedded" for p in db.patterns)


@pytest.mark.parametrize("pattern, sample, expected", [
    ("4D5A", b"xxMZyy", True),
    ("4D ?? 90", b"M\x00\x90", True),
    ("4D ?? 90", b"M\x90", False),
    ("41 [1-3] 42", b"A..B", True),
    ("41 [1-3] 42", b"A....B", False),
    ("0A", b"\n", True),
])
def test_compile_hex(pattern, sample, expected):
    regex, _ = compile_hex(pattern)
    assert (regex.search(sample) is not None) is expected


def test_compile_hex_reports_max_length():
    _, length = compile_hex("41 ?? [2-5] 42")
    assert length == 1 + 1 + 5 + 1


@pytest.mark.parametrize("entry", [
    {"type": "sha256", "value": "abc"},
    {"name": "x", "type": "sha256", "value": "zz" * 32},
    {"name": "x", "type": "md5", "value": "00" * 20},
    {"name": "x", "type": "rot13", "value": "abc"},
    {"name": "x", "type": "hex", "value": "4G"},
    {"name": "x", "type": "hex", "value": "41", "offset": -1},
])
def test_invalid_entries_are_rejected(entry):
    with pytest.raises(SignatureError):
        SignatureDB().add(entry)


def test_fingerprint_changes_with_content():
    a, b = SignatureDB(), SignatureDB()
    a.add({"name": "A", "type": "string", "value": "one"})
    b.add({"name": "A", "type": "string", "value": "two"})
    assert a.fingerprint() != b.fingerprint()


def test_load_file_errors_are_readable(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SignatureError, match="cannot read"):
        SignatureDB().load_file(bad)
