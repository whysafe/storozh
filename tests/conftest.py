import json

import pytest

from storozh.signatures import SignatureDB, load_databases

# A harmless marker used instead of EICAR whenever a test has to write a
# "bad" file to disk: real antivirus software would delete an EICAR file.
MARKER = "STOROZH-TEST-MARKER-7731"


@pytest.fixture
def test_db_file(tmp_path):
    path = tmp_path / "test-db.json"
    path.write_text(json.dumps({
        "name": "tests", "version": "1",
        "signatures": [{"name": "Test.Marker", "type": "string", "value": MARKER}],
    }), encoding="utf-8")
    return path


@pytest.fixture
def db(test_db_file) -> SignatureDB:
    return load_databases([str(test_db_file)])


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "storozh-home"
    monkeypatch.setenv("STOROZH_HOME", str(home))
    return home
