"""Command line interface: scan, quarantine, hash, eicar, db."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .cache import ScanCache
from .engine import ERROR, INFECTED, SKIPPED, SUSPICIOUS, FileResult, Scanner, ScanOptions
from .quarantine import Quarantine, QuarantineError, default_home
from .report import Console, Summary, to_html, to_json
from .signatures import SignatureError, eicar_bytes, load_databases, signature_entries_for
from .walker import parse_size, walk


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="storozh",
        description="Сторож: проверка файлов по сигнатурам и эвристикам.",
    )
    parser.add_argument("--version", action="version", version=f"storozh {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="проверить файлы и папки")
    scan.add_argument("paths", nargs="+", help="файлы и папки")
    scan.add_argument("--db", action="append", default=[], metavar="FILE", help="дополнительная база сигнатур (JSON)")
    scan.add_argument("--only-db", action="store_true", help="не загружать встроенную базу")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="исключить по маске")
    scan.add_argument("--max-size", default="200M", help="не проверять файлы больше (по умолчанию 200M)")
    scan.add_argument("--no-heuristics", action="store_true", help="только сигнатуры")
    scan.add_argument("--no-archives", action="store_true", help="не заглядывать внутрь zip/tar/gz")
    scan.add_argument("--quarantine", action="store_true", help="перенести заражённые файлы в карантин")
    scan.add_argument("--quarantine-suspicious", action="store_true", help="переносить и подозрительные")
    scan.add_argument("--cache", nargs="?", const="", default=None, metavar="FILE",
                      help="кэш вердиктов SQLite, пропускает неизменённые файлы")
    scan.add_argument("--json", action="store_true", help="вывести отчёт в JSON")
    scan.add_argument("--html", metavar="FILE", help="сохранить HTML-отчёт")
    scan.add_argument("-v", "--verbose", action="store_true", help="показывать и чистые файлы")
    scan.add_argument("--no-color", action="store_true", help="без цвета")

    q = sub.add_parser("quarantine", help="работа с карантином")
    qsub = q.add_subparsers(dest="action", required=True)
    qsub.add_parser("list", help="список файлов в карантине")
    restore = qsub.add_parser("restore", help="вернуть файл")
    restore.add_argument("id")
    restore.add_argument("--to", help="куда восстановить (по умолчанию на старое место)")
    restore.add_argument("--force", action="store_true", help="перезаписать существующий файл")
    delete = qsub.add_parser("delete", help="удалить файл из карантина навсегда")
    delete.add_argument("id")

    h = sub.add_parser("hash", help="сделать сигнатуру из известного вредного файла")
    h.add_argument("files", nargs="+")
    h.add_argument("--name", help="имя угрозы в базе")

    e = sub.add_parser("eicar", help="создать тестовый файл EICAR для проверки")
    e.add_argument("path", nargs="?", default="eicar.com")

    d = sub.add_parser("db", help="показать загруженные базы")
    d.add_argument("--db", action="append", default=[], metavar="FILE")
    return parser


def main(argv: list[str] | None = None) -> int:
    # A Windows console handles Unicode itself; pipes and files get UTF-8
    # instead of the legacy ANSI code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (SignatureError, QuarantineError, ValueError) as exc:
        print(f"storozh: {exc}", file=sys.stderr)
        return 2


def cmd_scan(args: argparse.Namespace) -> int:
    db = load_databases(args.db, include_default=not args.only_db)
    options = ScanOptions(heuristics=not args.no_heuristics, archives=not args.no_archives)
    scanner = Scanner(db, options)
    max_size = parse_size(args.max_size)
    quarantine_statuses = {INFECTED} | ({SUSPICIOUS} if args.quarantine_suspicious else set())
    vault = Quarantine() if args.quarantine or args.quarantine_suspicious else None

    console = Console(sys.stderr if args.json else sys.stdout, color=False if args.no_color else None,
                      verbose=args.verbose)
    summary = Summary(signatures=len(db), sources=db.sources)
    cache = None
    if args.cache is not None:
        profile = f"{db.fingerprint()}:{int(options.heuristics)}{int(options.archives)}:{__version__}"
        cache = ScanCache(args.cache or default_home() / "cache.sqlite", profile)

    started = time.perf_counter()
    try:
        for entry in walk(args.paths, args.exclude, max_size):
            result = _scan_entry(entry, scanner, cache)
            summary.results.append(result)
            qid = None
            if vault and result.status in quarantine_statuses:
                qid = _quarantine(vault, result)
                if qid:
                    summary.quarantined[result.path] = qid
            console.result(result, qid)
    finally:
        if cache:
            summary.cache_hits = cache.hits
            cache.close()
    summary.seconds = time.perf_counter() - started

    if args.json:
        print(to_json(summary))
    else:
        console.summary(summary)
    if args.html:
        Path(args.html).write_text(to_html(summary), encoding="utf-8")
        console.write(f"HTML-отчёт: {args.html}")
    return summary.exit_code


def _scan_entry(entry, scanner: Scanner, cache: ScanCache | None) -> FileResult:
    if entry.error:
        return FileResult(str(entry.path), status=ERROR, error=entry.error)
    if entry.skip_reason:
        return FileResult(str(entry.path), size=entry.size, status=SKIPPED, notes=[entry.skip_reason])
    if cache and (cached := cache.get(entry.path, entry.size, entry.mtime_ns)):
        return cached
    result = scanner.scan_file(entry.path)
    if cache:
        cache.put(entry.path, entry.size, entry.mtime_ns, result)
    return result


def _quarantine(vault: Quarantine, result: FileResult) -> str | None:
    try:
        return vault.add(result.path, [d.name for d in result.detections]).id
    except OSError as exc:
        result.notes.append(f"не удалось поместить в карантин: {exc}")
        return None


def cmd_quarantine(args: argparse.Namespace) -> int:
    vault = Quarantine()
    if args.action == "list":
        records = vault.list()
        if not records:
            print("Карантин пуст.")
        for r in records:
            print(f"{r.id}  {r.quarantined_at}  {', '.join(r.detections)}\n    {r.original_path}")
        return 0
    if args.action == "restore":
        print(f"Восстановлено: {vault.restore(args.id, args.to, args.force)}")
        return 0
    record = vault.delete(args.id)
    print(f"Удалено из карантина: {record.original_path}")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    entries = []
    for file in args.files:
        entries.extend(signature_entries_for(Path(file), args.name))
    print(json.dumps({"name": "custom", "version": "1", "signatures": entries}, indent=2, ensure_ascii=False))
    return 0


def cmd_eicar(args: argparse.Namespace) -> int:
    path = Path(args.path)
    path.write_bytes(eicar_bytes())
    print(f"Создан тестовый файл EICAR: {path}")
    print("Он безвреден, но установленный антивирус, скорее всего, сразу его удалит.")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    db = load_databases(args.db)
    for source in db.sources:
        print(source)
    for kind, table in db.hashes.items():
        print(f"  {kind:<7} {len(table)}")
    print(f"  pattern {len(db.patterns)}")
    print(f"Всего: {len(db)}, отпечаток {db.fingerprint()}")
    return 0


COMMANDS = {"scan": cmd_scan, "quarantine": cmd_quarantine, "hash": cmd_hash, "eicar": cmd_eicar, "db": cmd_db}
