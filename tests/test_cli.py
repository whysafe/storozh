import json
import zipfile

from storozh.cli import main

from .conftest import MARKER


def make_tree(tmp_path):
    root = tmp_path / "downloads"
    root.mkdir()
    (root / "notes.txt").write_text("ordinary notes", encoding="utf-8")
    (root / "bad.txt").write_text(MARKER, encoding="utf-8")
    (root / "invoice.pdf.exe").write_bytes(b"MZ")
    with zipfile.ZipFile(root / "pack.zip", "w") as zf:
        zf.writestr("inner/bad.txt", MARKER)
    return root


def test_clean_scan_exits_zero(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("fine")
    assert main(["scan", str(tmp_path), "--no-color"]) == 0
    assert "Заражено:            0" in capsys.readouterr().out


def test_scan_with_findings_exits_one(tmp_path, test_db_file, capsys):
    root = make_tree(tmp_path)
    code = main(["scan", str(root), "--db", str(test_db_file), "--no-color"])
    out = capsys.readouterr().out
    assert code == 1
    assert "Test.Marker" in out
    assert "pack.zip!inner/bad.txt" in out
    assert "Heuristic.DoubleExtension" in out


def test_json_output(tmp_path, test_db_file, capsys):
    root = make_tree(tmp_path)
    main(["scan", str(root), "--db", str(test_db_file), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["totals"]["infected"] == 2
    assert report["totals"]["suspicious"] == 1
    assert report["totals"]["clean"] == 1


def test_html_report(tmp_path, test_db_file):
    root = make_tree(tmp_path)
    out = tmp_path / "report.html"
    main(["scan", str(root), "--db", str(test_db_file), "--html", str(out), "--no-color"])
    page = out.read_text(encoding="utf-8")
    assert "Найдены угрозы" in page
    assert "pack.zip!inner/bad.txt" in page


def test_quarantine_flow(tmp_path, test_db_file, isolated_home, capsys):
    root = make_tree(tmp_path)
    main(["scan", str(root), "--db", str(test_db_file), "--quarantine", "--no-color"])
    assert not (root / "bad.txt").exists()
    assert (root / "invoice.pdf.exe").exists(), "suspicious files stay unless asked"
    capsys.readouterr()

    main(["quarantine", "list"])
    listing = capsys.readouterr().out
    first_id = listing.split()[0]
    assert main(["quarantine", "restore", first_id]) == 0
    assert "Восстановлено" in capsys.readouterr().out


def test_cache_reuses_verdicts(tmp_path, test_db_file, capsys):
    root = make_tree(tmp_path)
    cache = tmp_path / "cache.sqlite"
    args = ["scan", str(root), "--db", str(test_db_file), "--cache", str(cache), "--no-color"]
    main(args)
    capsys.readouterr()
    assert main(args) == 1
    assert "Из кэша:             4" in capsys.readouterr().out


def test_hash_command_output_is_a_loadable_db(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"some bytes")
    main(["hash", str(sample), "--name", "My.Sample"])
    db_file = tmp_path / "custom.json"
    db_file.write_text(capsys.readouterr().out, encoding="utf-8")
    assert main(["scan", str(sample), "--db", str(db_file), "--only-db", "--no-color"]) == 1


def test_bad_db_is_reported(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert main(["scan", str(tmp_path), "--db", str(bad)]) == 2
    assert "signatures" in capsys.readouterr().err


def test_db_command(capsys):
    assert main(["db"]) == 0
    assert "storozh-default" in capsys.readouterr().out
