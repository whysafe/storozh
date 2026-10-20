import gzip
import io
import tarfile
import zipfile

import pytest

from storozh import engine
from storozh.engine import Scanner, ScanOptions
from storozh.signatures import SignatureDB, eicar_bytes, load_default

from .conftest import MARKER


def zip_bytes(files: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def tar_gz_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def names(result):
    return [d.name for d in result.detections]


def test_eicar_is_detected_in_memory():
    result = Scanner(load_default()).scan_bytes(eicar_bytes(), "eicar.com")
    assert result.status == "infected"
    assert "EICAR-Test-File" in names(result)


def test_eicar_embedded_in_larger_file():
    data = b"header " * 100 + eicar_bytes() + b" trailer"
    result = Scanner(load_default()).scan_bytes(data, "notes.txt")
    assert names(result) == ["EICAR-Test-File.Embedded"]


def test_clean_data_is_clean(db):
    assert Scanner(db).scan_bytes(b"just some text", "a.txt").status == "clean"


def test_pattern_split_across_chunks(db, monkeypatch):
    monkeypatch.setattr(engine, "CHUNK", 16)
    data = b"x" * 13 + MARKER.encode() + b"y" * 40
    assert names(Scanner(db).scan_bytes(data, "f.bin")) == ["Test.Marker"]


def test_offset_pattern_only_matches_at_offset(monkeypatch):
    monkeypatch.setattr(engine, "CHUNK", 8)
    db = SignatureDB()
    db.add({"name": "Anchored", "type": "hex", "value": "CAFEBABE", "offset": 10})
    scanner = Scanner(db, ScanOptions(heuristics=False))
    assert names(scanner.scan_bytes(b"\0" * 10 + bytes.fromhex("CAFEBABE"))) == ["Anchored"]
    assert names(scanner.scan_bytes(b"\0" * 11 + bytes.fromhex("CAFEBABE"))) == []


def test_hash_signature(db):
    sample = b"known bad payload"
    import hashlib

    db.add({"name": "Known.Bad", "type": "sha1", "value": hashlib.sha1(sample).hexdigest()})
    assert names(Scanner(db).scan_bytes(sample, "x.bin")) == ["Known.Bad"]


def test_nested_zip_reports_full_location(db):
    inner = zip_bytes({"payload.txt": MARKER.encode()})
    outer = zip_bytes({"docs/inner.zip": inner, "readme.txt": b"hello"})
    result = Scanner(db).scan_bytes(outer, "outer.zip")
    assert result.status == "infected"
    assert result.detections[0].location == "outer.zip!docs/inner.zip!payload.txt"


def test_depth_limit_stops_recursion(db):
    data = MARKER.encode()
    for level in range(4):
        data = zip_bytes({f"l{level}.zip" if level else "m.txt": data})
    assert Scanner(db, ScanOptions(max_depth=2)).scan_bytes(data, "deep.zip").status == "clean"
    assert Scanner(db, ScanOptions(max_depth=5)).scan_bytes(data, "deep.zip").status == "infected"


def test_tar_gz_and_plain_gz(db):
    tgz = tar_gz_bytes({"src/evil.sh": MARKER.encode()})
    assert names(Scanner(db).scan_bytes(tgz, "a.tar.gz")) == ["Test.Marker"]
    gz = gzip.compress(MARKER.encode())
    result = Scanner(db).scan_bytes(gz, "log.txt.gz")
    assert result.detections[0].location == "log.txt"


def test_archives_can_be_disabled(db):
    data = zip_bytes({"m.txt": MARKER.encode()})
    assert Scanner(db, ScanOptions(archives=False)).scan_bytes(data, "a.zip").status == "clean"


def test_damaged_archive_is_a_note_not_a_crash(db):
    broken = zip_bytes({"a.txt": b"hello" * 100})[:60]
    result = Scanner(db).scan_bytes(broken, "broken.zip")
    assert result.status == "clean"
    assert any("damaged" in n for n in result.notes)


def test_decompression_bomb():
    bomb = zip_bytes({"zeros.bin": b"\0" * (11 * 1024 * 1024)})
    result = Scanner(SignatureDB()).scan_bytes(bomb, "big.zip")
    assert names(result) == ["Heuristic.DecompressionBomb"]
    assert result.status == "suspicious"


@pytest.mark.parametrize("name, data, expected", [
    ("invoice.pdf.exe", b"x", "Heuristic.DoubleExtension"),
    ("photo.jpg   .scr", b"x", "Heuristic.DoubleExtension"),
    ("report‮xcod.exe", b"x", "Heuristic.RTLO.Filename"),
    ("cat.jpg", b"MZ\x90\x00rest", "Heuristic.DisguisedExecutable"),
    ("song.mp3", b"\x7fELF\x02", "Heuristic.DisguisedExecutable"),
    ("AUTORUN.INF", b"[autorun]\r\nopen=setup.exe\r\n", "Heuristic.Autorun.Inf"),
])
def test_heuristics(name, data, expected):
    result = Scanner(SignatureDB()).scan_bytes(data, name)
    assert expected in names(result)
    assert result.status == "suspicious"


@pytest.mark.parametrize("name, data", [
    ("program.exe", b"MZ\x90"),
    ("archive.tar.gz", b"plain"),
    ("autorun.inf", b"[autorun]\nicon=disk.ico\n"),
    ("my.report.final.pdf", b"%PDF-1.7"),
])
def test_heuristics_do_not_flag_normal_files(name, data):
    assert Scanner(SignatureDB()).scan_bytes(data, name).status == "clean"


def test_macro_inside_docx_is_suspicious():
    docx = zip_bytes({"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"\0\1"})
    assert names(Scanner(SignatureDB()).scan_bytes(docx, "contract.docx")) == ["Heuristic.Office.HiddenMacro"]
    assert Scanner(SignatureDB()).scan_bytes(docx, "contract.docm").status == "clean"


def test_heuristics_can_be_disabled():
    result = Scanner(SignatureDB(), ScanOptions(heuristics=False)).scan_bytes(b"MZ", "a.pdf.exe")
    assert result.status == "clean"


def test_scan_file_missing_is_error(tmp_path, db):
    result = Scanner(db).scan_file(tmp_path / "nope.bin")
    assert result.status == "error"


def test_scan_file_on_disk(tmp_path, db):
    path = tmp_path / "x.txt"
    path.write_text(f"hello {MARKER} world", encoding="utf-8")
    result = Scanner(db).scan_file(path)
    assert result.status == "infected"
    assert result.size == path.stat().st_size
