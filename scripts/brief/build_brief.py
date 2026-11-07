# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Build kern_site/kern-institutional-brief.pdf from its HTML sources.

The brief has four pages, from two sources rendered with WeasyPrint:

1. brief.html, page 1: positioning, what KERN is, institutional value.
2. brief.html, page 2: use cases, comparison, status.
3. heimdall-page.html: the Heimdall explorer view.
4. brief.html, page 3: the legal notice.

Fonts are in fonts/ (SIL Open Font License, see the OFL-*.txt files), so
the output does not depend on fonts installed on the machine.

Usage, from the repository root:

    pip install weasyprint
    python scripts/brief/build_brief.py            # writes the PDF
    python scripts/brief/build_brief.py --check    # compares the text with
                                                   # the published PDF, writes
                                                   # nothing

WeasyPrint needs Pango. On Windows, run it under WSL or follow
https://doc.courtbouillon.org/weasyprint/stable/first_steps.html.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = ROOT / "kern_site" / "kern-institutional-brief.pdf"
EXPECTED_PAGES = 4


def build() -> bytes:
    from weasyprint import HTML  # imported here so --help works without it

    brief = HTML(filename=str(HERE / "brief.html"), base_url=str(HERE)).render()
    heimdall = HTML(filename=str(HERE / "heimdall-page.html"), base_url=str(HERE)).render()
    if len(brief.pages) != 3 or len(heimdall.pages) != 1:
        raise SystemExit(f"layout overflow: brief.html gives {len(brief.pages)} pages "
                         f"(expected 3), heimdall-page.html gives {len(heimdall.pages)} "
                         f"(expected 1)")
    pages = brief.pages[:2] + heimdall.pages + brief.pages[2:]
    pdf = brief.copy(pages).write_pdf()
    assert pdf is not None
    return pdf


def page_texts(data: bytes) -> list[str]:
    import io

    from pypdf import PdfReader

    return [" ".join((p.extract_text() or "").split()) for p in PdfReader(io.BytesIO(data)).pages]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="compare the text of a fresh build with the published PDF")
    args = ap.parse_args()
    pdf = build()
    if args.check:
        new, old = page_texts(pdf), page_texts(OUT.read_bytes())
        same = new == old
        for i, (a, b) in enumerate(zip(new, old), 1):
            if a != b:
                print(f"page {i}: text differs")
        if len(new) != len(old):
            print(f"page count differs: {len(new)} built, {len(old)} published")
        print("text identical to the published PDF" if same else "text differs")
        return 0 if same else 1
    OUT.write_bytes(pdf)
    print(f"wrote {OUT.relative_to(ROOT)}: {EXPECTED_PAGES} pages, {len(pdf)} bytes, "
          f"SHA256 {hashlib.sha256(pdf).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
