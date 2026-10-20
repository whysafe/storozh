"""Scan engine: streams a file once, matches hashes and patterns, recurses into archives."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import BinaryIO

from . import heuristics
from .signatures import SignatureDB

CHUNK = 1 << 20
HEADER_SIZE = 4096

CLEAN, INFECTED, SUSPICIOUS, ERROR, SKIPPED = "clean", "infected", "suspicious", "error", "skipped"


@dataclass
class Detection:
    name: str
    kind: str  # "signature" or "heuristic"
    location: str


@dataclass
class FileResult:
    path: str
    size: int = 0
    status: str = CLEAN
    detections: list[Detection] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None

    def finalize(self) -> "FileResult":
        if self.status in (ERROR, SKIPPED):
            return self
        kinds = {d.kind for d in self.detections}
        self.status = INFECTED if "signature" in kinds else SUSPICIOUS if kinds else CLEAN
        return self

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FileResult":
        detections = [Detection(**d) for d in data.get("detections", [])]
        return cls(**{**data, "detections": detections})


@dataclass
class ScanOptions:
    heuristics: bool = True
    archives: bool = True
    max_depth: int = 3
    max_member_size: int = 100 * 1024 * 1024
    max_archive_total: int = 500 * 1024 * 1024
    max_members: int = 10_000


class Scanner:
    def __init__(self, db: SignatureDB, options: ScanOptions | None = None):
        self.db = db
        self.options = options or ScanOptions()

    def scan_file(self, path: str | Path) -> FileResult:
        path = Path(path)
        result = FileResult(str(path))
        try:
            result.size = path.stat().st_size
            with path.open("rb") as fh:
                self._scan_stream(fh, str(path), 0, result)
        except OSError as exc:
            result.status, result.error = ERROR, exc.strerror or str(exc)
        return result.finalize()

    def scan_bytes(self, data: bytes, name: str = "<memory>") -> FileResult:
        result = FileResult(name, size=len(data))
        self._scan_stream(io.BytesIO(data), name, 0, result)
        return result.finalize()

    # --- internals -------------------------------------------------------

    def _scan_stream(self, fh: BinaryIO, name: str, depth: int, result: FileResult) -> None:
        def report(det_name: str, kind: str) -> None:
            result.detections.append(Detection(det_name, kind, name))

        header, matched = self._match_content(fh)
        for det in matched:
            report(det, "signature")

        if self.options.heuristics:
            for det in heuristics.check_name(name) + heuristics.check_header(name, header):
                report(det, "heuristic")

        if self.options.archives and depth < self.options.max_depth:
            fh.seek(0)
            self._scan_archive(fh, name, header, depth, result)

    def _match_content(self, fh: BinaryIO) -> tuple[bytes, list[str]]:
        """Single pass over the stream: hashes plus patterns with chunk overlap."""
        db = self.db
        hashers = {kind: hashlib.new(kind) for kind, table in db.hashes.items() if table}
        overlap = db.max_pattern_length - 1
        tail = b""
        consumed = 0  # absolute offset of the first byte of `tail`
        header = b""
        matched: list[str] = []
        pending = list(db.patterns)

        while chunk := fh.read(CHUNK):
            if len(header) < HEADER_SIZE:
                header += chunk[: HEADER_SIZE - len(header)]
            for h in hashers.values():
                h.update(chunk)
            window = tail + chunk
            still_pending = []
            for pattern in pending:
                if self._pattern_hits(pattern, window, consumed):
                    matched.append(pattern.name)
                elif pattern.offset is None or pattern.offset + pattern.length > consumed + len(window):
                    still_pending.append(pattern)
            pending = still_pending
            keep = min(overlap, len(window))
            consumed += len(window) - keep
            tail = window[len(window) - keep:] if keep else b""

        for kind, h in hashers.items():
            hit = db.hashes[kind].get(h.hexdigest())
            if hit and hit not in matched:
                matched.append(hit)
        return header, list(dict.fromkeys(matched))

    @staticmethod
    def _pattern_hits(pattern, window: bytes, window_start: int) -> bool:
        if pattern.offset is None:
            return pattern.regex.search(window) is not None
        local = pattern.offset - window_start
        return 0 <= local < len(window) and pattern.regex.match(window, local) is not None

    def _scan_archive(self, fh: BinaryIO, name: str, header: bytes, depth: int, result: FileResult) -> None:
        try:
            if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
                self._scan_zip(fh, name, depth, result)
            elif header[257:262] == b"ustar" or header[:2] == b"\x1f\x8b":
                self._scan_tar(fh, name, depth, result)
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            result.notes.append(f"{name}: archive is damaged ({exc})")

    def _scan_zip(self, fh: BinaryIO, name: str, depth: int, result: FileResult) -> None:
        opts = self.options
        with zipfile.ZipFile(fh) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            if self.options.heuristics:
                for det in heuristics.check_archive_members(name, [i.filename for i in infos]):
                    result.detections.append(Detection(det, "heuristic", name))
            budget = opts.max_archive_total
            for info in infos[: opts.max_members]:
                member = f"{name}!{info.filename}"
                if info.flag_bits & 0x1:
                    result.notes.append(f"{member}: encrypted, not scanned")
                    continue
                if opts.heuristics and heuristics.is_bomb(info.compress_size, info.file_size):
                    result.detections.append(Detection("Heuristic.DecompressionBomb", "heuristic", member))
                    continue
                if info.file_size > min(opts.max_member_size, budget):
                    result.notes.append(f"{member}: too large, not scanned")
                    continue
                budget -= info.file_size
                with archive.open(info) as src:
                    data = src.read(opts.max_member_size + 1)
                self._scan_stream(io.BytesIO(data), member, depth + 1, result)
            if len(infos) > opts.max_members:
                result.notes.append(f"{name}: only first {opts.max_members} entries scanned")

    def _scan_tar(self, fh: BinaryIO, name: str, depth: int, result: FileResult) -> None:
        opts = self.options
        if not _looks_like_tar(fh):
            # A plain .gz of a single file: scan the decompressed payload.
            import gzip

            fh.seek(0)
            with gzip.GzipFile(fileobj=fh) as gz:
                data = gz.read(opts.max_member_size + 1)
            if len(data) > opts.max_member_size:
                result.notes.append(f"{name}: unpacked data too large, not scanned")
                return
            inner = name[:-3] if name.lower().endswith(".gz") else name + "!data"
            self._scan_stream(io.BytesIO(data), inner, depth + 1, result)
            return
        fh.seek(0)
        budget = opts.max_archive_total
        with tarfile.open(fileobj=fh, mode="r:*") as archive:
            for count, info in enumerate(archive):
                if count >= opts.max_members:
                    result.notes.append(f"{name}: only first {opts.max_members} entries scanned")
                    break
                if not info.isfile():
                    continue
                member = f"{name}!{info.name}"
                if info.size > min(opts.max_member_size, budget):
                    result.notes.append(f"{member}: too large, not scanned")
                    continue
                budget -= info.size
                src = archive.extractfile(info)
                if src is None:
                    continue
                self._scan_stream(io.BytesIO(src.read()), member, depth + 1, result)


def _looks_like_tar(fh: BinaryIO) -> bool:
    fh.seek(0)
    try:
        with tarfile.open(fileobj=fh, mode="r:*") as archive:
            archive.next()
        return True
    except (tarfile.TarError, EOFError, OSError):
        return False
