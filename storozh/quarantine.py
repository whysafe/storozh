"""Quarantine: detected files are moved away and XOR-masked so they cannot be run by accident."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

MASK = 0xA5
CHUNK = 1 << 20


class QuarantineError(Exception):
    pass


@dataclass
class Record:
    id: str
    original_path: str
    sha256: str
    size: int
    detections: list[str]
    quarantined_at: str


def default_home() -> Path:
    return Path(os.environ.get("STOROZH_HOME") or Path.home() / ".storozh")


_MASK_TABLE = bytes(b ^ MASK for b in range(256))


def _mask(data: bytes) -> bytes:
    return data.translate(_MASK_TABLE)


class Quarantine:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else default_home() / "quarantine"

    def _paths(self, record_id: str) -> tuple[Path, Path]:
        if not record_id.isalnum():
            raise QuarantineError(f"bad quarantine id {record_id!r}")
        return self.root / f"{record_id}.bin", self.root / f"{record_id}.json"

    def add(self, path: str | Path, detections: list[str]) -> Record:
        source = Path(path)
        self.root.mkdir(parents=True, exist_ok=True)
        record_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + secrets.token_hex(3)
        blob, meta = self._paths(record_id)
        digest = hashlib.sha256()
        size = 0
        with source.open("rb") as src, blob.open("wb") as dst:
            while chunk := src.read(CHUNK):
                digest.update(chunk)
                size += len(chunk)
                dst.write(_mask(chunk))
        record = Record(
            id=record_id,
            original_path=str(source.resolve()),
            sha256=digest.hexdigest(),
            size=size,
            detections=sorted(set(detections)),
            quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        meta.write_text(json.dumps(asdict(record), ensure_ascii=False, indent=2), encoding="utf-8")
        source.unlink()
        return record

    def list(self) -> list[Record]:
        if not self.root.is_dir():
            return []
        records = []
        for meta in sorted(self.root.glob("*.json")):
            try:
                records.append(Record(**json.loads(meta.read_text(encoding="utf-8"))))
            except (ValueError, TypeError):
                continue
        return records

    def get(self, record_id: str) -> Record:
        blob, meta = self._paths(record_id)
        if not meta.exists() or not blob.exists():
            raise QuarantineError(f"no quarantined file with id {record_id}")
        return Record(**json.loads(meta.read_text(encoding="utf-8")))

    def restore(self, record_id: str, target: str | Path | None = None, force: bool = False) -> Path:
        record = self.get(record_id)
        blob, meta = self._paths(record_id)
        destination = Path(target) if target else Path(record.original_path)
        if destination.is_dir():
            destination = destination / Path(record.original_path).name
        if destination.exists() and not force:
            raise QuarantineError(f"{destination} already exists, use --force to overwrite")
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with blob.open("rb") as src, destination.open("wb") as dst:
            while chunk := src.read(CHUNK):
                plain = _mask(chunk)
                digest.update(plain)
                dst.write(plain)
        if digest.hexdigest() != record.sha256:
            destination.unlink()
            raise QuarantineError("quarantined copy is corrupted, checksum mismatch")
        blob.unlink()
        meta.unlink()
        return destination

    def delete(self, record_id: str) -> Record:
        record = self.get(record_id)
        for path in self._paths(record_id):
            path.unlink()
        return record
