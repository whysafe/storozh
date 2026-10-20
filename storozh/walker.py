"""Walks the given paths and yields files to scan, honouring exclusions and size limits."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class Entry:
    path: Path
    size: int
    mtime_ns: int
    skip_reason: str | None = None
    error: str | None = None


def parse_size(text: str) -> int:
    """'100M' -> 104857600. Accepts plain bytes and K/M/G suffixes."""
    text = text.strip().upper().removesuffix("B")
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    factor = units.get(text[-1:], 1)
    number = text[:-1] if text[-1:] in units else text
    try:
        value = float(number)
    except ValueError:
        raise ValueError(f"cannot parse size {text!r}") from None
    if value < 0:
        raise ValueError("size must be positive")
    return int(value * factor)


def is_excluded(path: Path, patterns: list[str]) -> bool:
    posix = path.as_posix()
    return any(fnmatch.fnmatch(path.name, p) or fnmatch.fnmatch(posix, p) for p in patterns)


def walk(paths: list[str], exclude: list[str] | None = None, max_size: int | None = None) -> Iterator[Entry]:
    exclude = exclude or []
    for raw in paths:
        root = Path(raw)
        if root.is_dir() and not root.is_symlink():
            yield from _walk_dir(root, exclude, max_size)
        elif root.exists():
            if not is_excluded(root, exclude):
                yield _entry(root, max_size)
        else:
            yield Entry(root, 0, 0, error="no such file or directory")


def _walk_dir(root: Path, exclude: list[str], max_size: int | None) -> Iterator[Entry]:
    errors: list[OSError] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=errors.append):
        base = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(base / d, exclude) and not (base / d).is_symlink())
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink() or is_excluded(path, exclude):
                continue
            yield _entry(path, max_size)
        while errors:
            err = errors.pop()
            yield Entry(Path(err.filename or dirpath), 0, 0, error=err.strerror or str(err))


def _entry(path: Path, max_size: int | None) -> Entry:
    try:
        st = path.stat()
    except OSError as exc:
        return Entry(path, 0, 0, error=exc.strerror or str(exc))
    if max_size is not None and st.st_size > max_size:
        return Entry(path, st.st_size, st.st_mtime_ns, skip_reason="larger than --max-size")
    return Entry(path, st.st_size, st.st_mtime_ns)
