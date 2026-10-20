"""Signature database: loading, validation and compiling into matchers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

HASH_TYPES = ("md5", "sha1", "sha256")
PATTERN_TYPES = ("hex", "string")

# The EICAR test file is stored as hex so that this source file itself
# is not flagged by real antivirus software.
EICAR_HEX = (
    "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
    "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
)


def eicar_bytes() -> bytes:
    return bytes.fromhex(EICAR_HEX)


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[bytes]
    length: int
    offset: int | None  # None means "anywhere in the file"


@dataclass
class SignatureDB:
    hashes: dict[str, dict[str, str]] = field(default_factory=lambda: {t: {} for t in HASH_TYPES})
    patterns: list[Pattern] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    _raw: list[dict] = field(default_factory=list, repr=False)

    def __len__(self) -> int:
        return sum(len(v) for v in self.hashes.values()) + len(self.patterns)

    @property
    def max_pattern_length(self) -> int:
        return max((p.length for p in self.patterns), default=1)

    def fingerprint(self) -> str:
        """Stable digest of all loaded signatures, used to invalidate the scan cache."""
        payload = json.dumps(sorted(self._raw, key=lambda s: json.dumps(s, sort_keys=True)), sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def add(self, entry: dict, source: str = "<memory>") -> None:
        name = entry.get("name")
        kind = entry.get("type")
        value = entry.get("value")
        if not isinstance(name, str) or not name:
            raise SignatureError(f"{source}: signature without a name: {entry!r}")
        if not isinstance(value, str) or not value:
            raise SignatureError(f"{source}: signature {name!r} has no value")

        if kind in HASH_TYPES:
            digest = value.lower()
            expected = hashlib.new(kind).digest_size * 2
            if len(digest) != expected or not re.fullmatch(r"[0-9a-f]+", digest):
                raise SignatureError(f"{source}: {name!r} is not a valid {kind} digest")
            self.hashes[kind][digest] = name
        elif kind in PATTERN_TYPES:
            offset = entry.get("offset")
            if offset is not None and (not isinstance(offset, int) or offset < 0):
                raise SignatureError(f"{source}: {name!r} has a bad offset {offset!r}")
            regex, length = compile_hex(value) if kind == "hex" else compile_string(value)
            self.patterns.append(Pattern(name, regex, length, offset))
        else:
            raise SignatureError(f"{source}: {name!r} has unknown type {kind!r}")
        self._raw.append(entry)

    def load_file(self, path: str | Path) -> None:
        path = Path(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SignatureError(f"cannot read signature file {path}: {exc}") from exc
        self._load_document(data, str(path))

    def _load_document(self, data: dict, source: str) -> None:
        entries = data.get("signatures") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise SignatureError(f"{source}: expected an object with a 'signatures' list")
        for entry in entries:
            self.add(entry, source)
        self.sources.append(f"{data.get('name', source)} {data.get('version', '')}".strip())


def compile_hex(value: str) -> tuple[re.Pattern[bytes], int]:
    """Compile a hex pattern like ``4D5A ?? 00 [2-4] 50`` into a bytes regex.

    ``??`` matches any byte, ``[a-b]`` skips between a and b arbitrary bytes.
    """
    tokens = re.findall(r"\[\d+-\d+\]|\?\?|[0-9A-Fa-f]{2}|\S", value.replace(" ", ""))
    parts: list[bytes] = []
    length = 0
    for token in tokens:
        if token == "??":
            parts.append(b".")
            length += 1
        elif token.startswith("["):
            low, high = map(int, token[1:-1].split("-"))
            if low > high:
                raise SignatureError(f"bad jump {token} in pattern {value!r}")
            parts.append(b".{%d,%d}" % (low, high))
            length += high
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            parts.append(re.escape(bytes.fromhex(token)))
            length += 1
        else:
            raise SignatureError(f"bad token {token!r} in hex pattern {value!r}")
    if not parts:
        raise SignatureError("empty hex pattern")
    return re.compile(b"".join(parts), re.DOTALL), length


def compile_string(value: str) -> tuple[re.Pattern[bytes], int]:
    raw = value.encode("utf-8")
    return re.compile(re.escape(raw)), len(raw)


def load_default() -> SignatureDB:
    db = SignatureDB()
    text = resources.files("storozh").joinpath("data/default.json").read_text(encoding="utf-8")
    db._load_document(json.loads(text), "default.json")
    return db


def load_databases(paths: list[str] | None, include_default: bool = True) -> SignatureDB:
    db = load_default() if include_default else SignatureDB()
    for path in paths or []:
        db.load_file(path)
    return db


def signature_entries_for(path: Path, name: str | None = None) -> list[dict]:
    """Build ready-to-paste signature entries for a known bad file."""
    hashers = {t: hashlib.new(t) for t in HASH_TYPES}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for h in hashers.values():
                h.update(chunk)
    label = name or f"Custom.{path.stem}"
    return [{"name": label, "type": t, "value": hashers[t].hexdigest()} for t in ("sha256", "md5")]
