"""Scan summary and the three output formats: console, JSON and a standalone HTML page."""

from __future__ import annotations

import html
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime

from . import __version__
from .engine import CLEAN, ERROR, INFECTED, SKIPPED, SUSPICIOUS, FileResult


@dataclass
class Summary:
    results: list[FileResult] = field(default_factory=list)
    started: datetime = field(default_factory=datetime.now)
    seconds: float = 0.0
    signatures: int = 0
    sources: list[str] = field(default_factory=list)
    cache_hits: int = 0
    quarantined: dict[str, str] = field(default_factory=dict)  # path -> quarantine id

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def scanned_bytes(self) -> int:
        return sum(r.size for r in self.results if r.status not in (ERROR, SKIPPED))

    @property
    def threats(self) -> list[FileResult]:
        return [r for r in self.results if r.status in (INFECTED, SUSPICIOUS)]

    @property
    def exit_code(self) -> int:
        if self.threats:
            return 1
        return 2 if self.count(ERROR) else 0

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "started": self.started.isoformat(timespec="seconds"),
            "seconds": round(self.seconds, 3),
            "signatures": self.signatures,
            "databases": self.sources,
            "totals": {s: self.count(s) for s in (CLEAN, INFECTED, SUSPICIOUS, ERROR, SKIPPED)},
            "scanned_bytes": self.scanned_bytes,
            "cache_hits": self.cache_hits,
            "results": [
                {**r.to_dict(), "quarantine_id": self.quarantined.get(r.path)}
                for r in self.results
                if r.status != CLEAN
            ],
        }


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024 or unit == "ГБ":
            return f"{value:.0f} {unit}" if unit == "Б" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} Б"


class Console:
    COLORS = {INFECTED: "31;1", SUSPICIOUS: "33;1", ERROR: "35", SKIPPED: "2", CLEAN: "32", "dim": "2", "bold": "1"}
    LABELS = {INFECTED: "НАЙДЕНО", SUSPICIOUS: "ПОДОЗР.", ERROR: "ОШИБКА", SKIPPED: "ПРОПУСК", CLEAN: "ЧИСТО"}

    def __init__(self, stream=None, color: bool | None = None, verbose: bool = False):
        self.stream = stream or sys.stdout
        if color is None:
            color = self.stream.isatty() and "NO_COLOR" not in os.environ
        self.color = color
        self.verbose = verbose

    def paint(self, text: str, style: str) -> str:
        return f"\033[{self.COLORS[style]}m{text}\033[0m" if self.color else text

    def write(self, text: str = "") -> None:
        print(text, file=self.stream)

    def result(self, result: FileResult, quarantine_id: str | None = None) -> None:
        if result.status == CLEAN and not self.verbose:
            return
        if result.status == SKIPPED and not self.verbose:
            return
        label = self.paint(f"{self.LABELS[result.status]:<8}", result.status)
        if result.status in (INFECTED, SUSPICIOUS):
            for det in result.detections:
                self.write(f"{label} {det.location}  {self.paint(det.name, 'bold')}")
            if quarantine_id:
                self.write(self.paint(f"         -> в карантине, id {quarantine_id}", "dim"))
        elif result.status == ERROR:
            self.write(f"{label} {result.path}  {result.error}")
        else:
            self.write(f"{label} {result.path}")
        if self.verbose:
            for note in result.notes:
                self.write(self.paint(f"         {note}", "dim"))

    def summary(self, s: Summary) -> None:
        line = "-" * 44
        self.write(self.paint(line, "dim"))
        self.write(f"Сигнатур загружено:  {s.signatures}")
        self.write(f"Проверено файлов:    {len(s.results) - s.count(ERROR) - s.count(SKIPPED)} ({human_size(s.scanned_bytes)})")
        if s.cache_hits:
            self.write(f"Из кэша:             {s.cache_hits}")
        self.write(f"Заражено:            {self.paint(str(s.count(INFECTED)), INFECTED) if s.count(INFECTED) else 0}")
        self.write(f"Подозрительно:       {self.paint(str(s.count(SUSPICIOUS)), SUSPICIOUS) if s.count(SUSPICIOUS) else 0}")
        if s.count(SKIPPED):
            self.write(f"Пропущено:           {s.count(SKIPPED)}")
        if s.count(ERROR):
            self.write(f"Ошибок доступа:      {s.count(ERROR)}")
        if s.quarantined:
            self.write(f"В карантин:          {len(s.quarantined)}")
        self.write(f"Время:               {s.seconds:.2f} с")


def to_json(summary: Summary) -> str:
    return json.dumps(summary.to_dict(), ensure_ascii=False, indent=2)


_STATUS_RU = {INFECTED: "Заражён", SUSPICIOUS: "Подозрительный", ERROR: "Ошибка", SKIPPED: "Пропущен"}


def to_html(summary: Summary) -> str:
    e = html.escape
    rows = []
    for r in summary.results:
        if r.status == CLEAN:
            continue
        if r.detections:
            what = "".join(
                f'<div class="det"><b>{e(d.name)}</b>'
                + (f'<span>{e(d.location)}</span>' if d.location != r.path else "")
                + "</div>"
                for d in r.detections
            )
        else:
            what = f'<div class="det"><span>{e(r.error or "; ".join(r.notes) or "")}</span></div>'
        qid = summary.quarantined.get(r.path)
        q = f'<small>карантин: {e(qid)}</small>' if qid else ""
        rows.append(
            f'<tr class="s-{r.status}"><td><span class="pill">{_STATUS_RU[r.status]}</span></td>'
            f'<td class="path">{e(r.path)}{q}</td><td>{what}</td><td class="num">{human_size(r.size)}</td></tr>'
        )
    verdict_cls = "bad" if summary.count(INFECTED) else "warn" if summary.threats else "ok"
    verdict = {
        "bad": "Найдены угрозы",
        "warn": "Есть подозрительные файлы",
        "ok": "Угроз не найдено",
    }[verdict_cls]
    table = (
        "<table><thead><tr><th>Статус</th><th>Файл</th><th>Обнаружение</th><th>Размер</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else '<p class="empty">Все проверенные файлы чистые.</p>'
    )
    cards = [
        ("Проверено", str(len(summary.results) - summary.count(ERROR) - summary.count(SKIPPED))),
        ("Объём", human_size(summary.scanned_bytes)),
        ("Заражено", str(summary.count(INFECTED))),
        ("Подозрительно", str(summary.count(SUSPICIOUS))),
        ("Ошибок", str(summary.count(ERROR))),
        ("Время", f"{summary.seconds:.2f} с"),
    ]
    card_html = "".join(f'<div class="card"><span>{k}</span><strong>{v}</strong></div>' for k, v in cards)
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт Сторожа · {summary.started:%d.%m.%Y %H:%M}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Onest:wght@400;600;800&family=Martian+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head>
<body>
<header class="top">
  <div class="brand"><span class="shield" aria-hidden="true"></span>Сторож <em>v{__version__}</em></div>
  <div class="meta">{summary.started:%d.%m.%Y, %H:%M} · сигнатур: {summary.signatures} · {e(", ".join(summary.sources))}</div>
</header>
<main>
  <section class="verdict v-{verdict_cls}"><h1>{verdict}</h1></section>
  <section class="cards">{card_html}</section>
  <section class="list"><h2>Что найдено</h2>{table}</section>
</main>
<footer>Отчёт создан утилитой storozh · github.com/whysafe/storozh</footer>
</body>
</html>
"""


_CSS = """
:root{--bg:#f3efe6;--paper:#fffdf8;--ink:#1d2a24;--muted:#5d6b63;--line:#ddd5c4;
--pine:#1f4d3a;--bad:#b3261e;--bad-bg:#fbe3df;--warn:#8a5a00;--warn-bg:#fdf0cf;--ok:#1f6b45;--ok-bg:#dcefe3}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 Onest,system-ui,sans-serif}
.top{background:var(--pine);color:#f3efe6;padding:20px clamp(16px,4vw,48px);display:flex;flex-wrap:wrap;
gap:8px 24px;align-items:center;justify-content:space-between}
.brand{font-weight:800;font-size:1.4rem;display:flex;align-items:center;gap:10px}
.brand em{font:400 .8rem 'Martian Mono',monospace;opacity:.7;font-style:normal}
.shield{width:22px;height:26px;background:#e9c46a;clip-path:polygon(50% 0,100% 18%,92% 70%,50% 100%,8% 70%,0 18%)}
.meta{font:400 .78rem 'Martian Mono',monospace;opacity:.85;overflow-wrap:anywhere}
main{max-width:1100px;margin:0 auto;padding:28px clamp(16px,4vw,48px) 48px}
.verdict{border-radius:14px;padding:22px 26px;margin-bottom:22px;border:1px solid}
.verdict h1{margin:0;font-size:clamp(1.4rem,3.5vw,2.1rem);font-weight:800;letter-spacing:-.01em}
.v-bad{background:var(--bad-bg);color:var(--bad);border-color:#f0b8b1}
.v-warn{background:var(--warn-bg);color:var(--warn);border-color:#ecd28e}
.v-ok{background:var(--ok-bg);color:var(--ok);border-color:#a9d5ba}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:30px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card span{display:block;color:var(--muted);font-size:.85rem}
.card strong{font:600 1.35rem 'Martian Mono',monospace}
h2{font-size:1.15rem;margin:0 0 12px}
.list{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:20px;overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:640px}
th{text-align:left;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
padding:8px 10px;border-bottom:2px solid var(--line)}
td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.path{font:400 .82rem 'Martian Mono',monospace;overflow-wrap:anywhere;max-width:360px}
.path small{display:block;color:var(--muted);margin-top:4px}
.det{margin-bottom:6px}.det b{display:block;font-weight:600}
.det span{font:400 .75rem 'Martian Mono',monospace;color:var(--muted);overflow-wrap:anywhere}
.num{white-space:nowrap;text-align:right;font-family:'Martian Mono',monospace;font-size:.85rem}
.pill{display:inline-block;padding:3px 10px;border-radius:99px;font-size:.78rem;font-weight:600;white-space:nowrap}
.s-infected .pill{background:var(--bad-bg);color:var(--bad)}
.s-suspicious .pill{background:var(--warn-bg);color:var(--warn)}
.s-error .pill,.s-skipped .pill{background:#ebe6db;color:var(--muted)}
.empty{color:var(--muted);margin:0}
footer{text-align:center;color:var(--muted);font-size:.8rem;padding:0 16px 32px}
@media (max-width:700px){
.list{padding:16px}
table{min-width:0}thead{display:none}
tr{display:grid;grid-template-columns:1fr auto;gap:6px 12px;padding:14px 0;border-bottom:1px solid var(--line)}
td{padding:0;border:0}.path{max-width:none;grid-column:1/-1;grid-row:2}
td:nth-child(3){grid-column:1/-1}.num{grid-column:2;grid-row:1}
}
"""
