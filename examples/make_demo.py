"""Creates a folder of harmless sample files that trip every kind of detection.

Instead of EICAR it uses a marker string from examples/custom-db.json, so
Windows Defender and other real antivirus software leave the files alone.

    python examples/make_demo.py demo
    storozh scan demo --db examples/custom-db.json --html report.html
"""

import io
import sys
import zipfile
from pathlib import Path

MARKER = b"STOROZH-DEMO-MARKER: this file pretends to be malware"


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def main(target: str) -> None:
    root = Path(target)
    (root / "Загрузки").mkdir(parents=True, exist_ok=True)
    (root / "Флешка").mkdir(exist_ok=True)
    (root / "Документы").mkdir(exist_ok=True)

    (root / "Документы" / "отчёт.txt").write_text("Квартальный отчёт, всё в порядке.\n", encoding="utf-8")
    (root / "Документы" / "keygen.txt").write_bytes(b"license helper\n" + MARKER)
    (root / "Загрузки" / "счёт_на_оплату.pdf.exe").write_bytes(b"MZ\x90\x00" + b"\0" * 60)
    (root / "Загрузки" / "котик.jpg").write_bytes(b"MZ\x90\x00" + b"\0" * 60)
    (root / "Загрузки" / "договор.docx").write_bytes(
        zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>", "word/vbaProject.bin": b"\xd0\xcf"})
    )
    inner = zip_bytes({"crack/setup.txt": MARKER})
    (root / "Загрузки" / "игра_repack.zip").write_bytes(zip_bytes({"readme.txt": b"enjoy", "bonus.zip": inner}))
    (root / "Флешка" / "autorun.inf").write_text("[autorun]\nopen=update.exe\nicon=drive.ico\n", encoding="ascii")
    print(f"Демо-папка создана: {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo")
