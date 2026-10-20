"""Cheap, explainable heuristics that catch common tricks without signatures."""

from __future__ import annotations

import re

DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "avi", "mkv", "mov", "wav",
}
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "wsf",
    "ps1", "hta", "lnk", "jar", "cpl",
}
MACRO_FREE_OFFICE = {"docx", "xlsx", "pptx"}

_DOUBLE_EXT = re.compile(
    r"\.(%s)[\s._-]*\.(%s)$" % ("|".join(sorted(DOCUMENT_EXTENSIONS)), "|".join(sorted(EXECUTABLE_EXTENSIONS))),
    re.IGNORECASE,
)
_AUTORUN_ACTION = re.compile(rb"^\s*(open|shellexecute|shell\\[^=]*\\command)\s*=", re.IGNORECASE | re.MULTILINE)

RTLO = "‮"

# A compressed member that unpacks to more than this many times its size
# (and is big enough to matter) is treated as a decompression bomb.
BOMB_RATIO = 100
BOMB_MIN_SIZE = 10 * 1024 * 1024


def extension(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def check_name(name: str) -> list[str]:
    base = basename(name)
    found = []
    if RTLO in base:
        found.append("Heuristic.RTLO.Filename")
    if _DOUBLE_EXT.search(base):
        found.append("Heuristic.DoubleExtension")
    return found


def check_header(name: str, header: bytes) -> list[str]:
    ext = extension(name)
    found = []
    is_pe = header[:2] == b"MZ"
    is_elf = header[:4] == b"\x7fELF"
    if (is_pe or is_elf) and ext in DOCUMENT_EXTENSIONS:
        found.append("Heuristic.DisguisedExecutable")
    if basename(name).lower() == "autorun.inf" and _AUTORUN_ACTION.search(header):
        found.append("Heuristic.Autorun.Inf")
    return found


def check_archive_members(name: str, members: list[str]) -> list[str]:
    if extension(name) in MACRO_FREE_OFFICE and any(m.lower().endswith("vbaproject.bin") for m in members):
        return ["Heuristic.Office.HiddenMacro"]
    return []


def is_bomb(compressed: int, uncompressed: int) -> bool:
    return uncompressed >= BOMB_MIN_SIZE and uncompressed > max(compressed, 1) * BOMB_RATIO
