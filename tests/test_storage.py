import os

import pytest

from storozh.cache import ScanCache
from storozh.engine import Scanner
from storozh.quarantine import Quarantine, QuarantineError
from storozh.walker import parse_size, walk

from .conftest import MARKER


@pytest.mark.parametrize("text, expected", [("100", 100), ("1K", 1024), ("1.5M", 1572864), ("2gb", 2 << 30)])
def test_parse_size(text, expected):
    assert parse_size(text) == expected


def test_parse_size_rejects_garbage():
    with pytest.raises(ValueError):
        parse_size("lots")


def test_walk_excludes_and_limits(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "src" / "a.py").write_text("a")
    (tmp_path / "src" / "big.iso").write_bytes(b"\0" * 2048)
    (tmp_path / "node_modules" / "lib.js").write_text("x")
    (tmp_path / "debug.log").write_text("x")

    entries = {e.path.name: e for e in walk([str(tmp_path)], ["node_modules", "*.log"], max_size=1024)}
    assert set(entries) == {"a.py", "big.iso"}
    assert entries["big.iso"].skip_reason
    assert entries["a.py"].skip_reason is None


def test_walk_reports_missing_path(tmp_path):
    [entry] = walk([str(tmp_path / "missing")])
    assert entry.error


def make_bad_file(tmp_path, name="bad.txt"):
    path = tmp_path / name
    path.write_text(MARKER, encoding="utf-8")
    return path


def test_quarantine_roundtrip(tmp_path):
    vault = Quarantine(tmp_path / "q")
    bad = make_bad_file(tmp_path)
    record = vault.add(bad, ["Test.Marker"])

    assert not bad.exists()
    stored = (tmp_path / "q" / f"{record.id}.bin").read_bytes()
    assert MARKER.encode() not in stored, "quarantined data must be masked"
    assert [r.id for r in vault.list()] == [record.id]

    restored = vault.restore(record.id)
    assert restored.read_text(encoding="utf-8") == MARKER
    assert vault.list() == []


def test_quarantine_restore_refuses_overwrite(tmp_path):
    vault = Quarantine(tmp_path / "q")
    bad = make_bad_file(tmp_path)
    record = vault.add(bad, ["Test.Marker"])
    bad.write_text("new file in the same place")
    with pytest.raises(QuarantineError, match="already exists"):
        vault.restore(record.id)
    vault.restore(record.id, force=True)
    assert bad.read_text(encoding="utf-8") == MARKER


def test_quarantine_detects_corruption(tmp_path):
    vault = Quarantine(tmp_path / "q")
    record = vault.add(make_bad_file(tmp_path), ["Test.Marker"])
    blob = tmp_path / "q" / f"{record.id}.bin"
    blob.write_bytes(blob.read_bytes()[:-1] + b"\x00")
    with pytest.raises(QuarantineError, match="corrupted"):
        vault.restore(record.id, tmp_path / "out.txt")
    assert not (tmp_path / "out.txt").exists()


def test_quarantine_delete_and_bad_ids(tmp_path):
    vault = Quarantine(tmp_path / "q")
    record = vault.add(make_bad_file(tmp_path), ["Test.Marker"])
    vault.delete(record.id)
    assert vault.list() == []
    with pytest.raises(QuarantineError):
        vault.get("../../etc/passwd")


def test_cache_hit_and_invalidation(tmp_path, db):
    target = make_bad_file(tmp_path)
    st = target.stat()
    result = Scanner(db).scan_file(target)

    with ScanCache(tmp_path / "c.sqlite", "profile-a") as cache:
        cache.put(target, st.st_size, st.st_mtime_ns, result)
    with ScanCache(tmp_path / "c.sqlite", "profile-a") as cache:
        cached = cache.get(target, st.st_size, st.st_mtime_ns)
        assert cached.status == "infected" and cached.detections[0].name == "Test.Marker"
        assert cache.get(target, st.st_size, st.st_mtime_ns + 1) is None
    with ScanCache(tmp_path / "c.sqlite", "profile-b") as cache:
        assert cache.get(target, st.st_size, st.st_mtime_ns) is None


def test_quarantine_default_home_from_env(isolated_home):
    assert Quarantine().root == isolated_home / "quarantine"
    assert os.environ["STOROZH_HOME"] == str(isolated_home)
