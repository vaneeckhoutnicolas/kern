# Institutional brief: source

`kern_site/kern-institutional-brief.pdf` is built from the files in this
folder:

| File | Pages of the PDF |
|---|---|
| `brief.html` | 1 (positioning), 2 (use cases, comparison, status), 4 (legal notice) |
| `heimdall-page.html` | 3 (Heimdall explorer view) |
| `build_brief.py` | renders both with WeasyPrint and assembles the four pages |
| `fonts/` | Fraunces, Instrument Sans, JetBrains Mono, Noto Sans Runic (SIL Open Font License, `OFL-*.txt`) |

## Build

From the repository root:

```
pip install weasyprint pypdf
python scripts/brief/build_brief.py           # writes kern_site/kern-institutional-brief.pdf
python scripts/brief/build_brief.py --check   # compares the text with the published PDF
```

The script stops if a source overflows its page count (three pages for
`brief.html`, one for `heimdall-page.html`). WeasyPrint needs Pango; on
Windows, run it under WSL.

## When to rebuild

Any change to the facts the brief states: the test count (page 2, status
strip), the staking description (page 1, point 2, and page 2, KRN
paragraph), the network path, the legal notice. Edit the HTML, rebuild,
check the four pages, and commit the PDF with its source.

## Provenance

The sources were written in June 2026 and were not in the repository.
They were recovered on 7 November 2026 from the working sessions in which
the brief was made, replaying every recorded edit; rendered again, they
give text identical to the published PDF of that time on every page. The
corrections made directly in the PDF on 7 November 2026 are now in the
source: "Bonded Proof-of-Stake" and its description, "bonded-PoS
collateral", and the test count.
