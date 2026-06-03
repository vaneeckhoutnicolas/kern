#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
Build whitepaper.html from docs/whitepaper.md.

Reads the markdown whitepaper, converts to HTML with extensions,
auto-generates the sidebar table of contents from headings, computes
reading time, then renders into the Nordic editorial template.

Re-run this whenever the whitepaper is updated:

    python3 build_whitepaper.py

Inputs:
    ../kern/docs/whitepaper.md  (resolved relative to this script)
    OR: pass --source PATH

Outputs:
    whitepaper.html (next to index.html)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from datetime import datetime

import markdown

HERE = Path(__file__).resolve().parent
DEFAULT_SOURCE = HERE / "../docs/whitepaper.md"
DEFAULT_OUT    = HERE / "whitepaper.html"


# ============================================================================
# Markdown → HTML conversion
# ============================================================================

def convert_markdown(text: str) -> tuple[str, list[dict]]:
    """Convert markdown to HTML and return (body_html, toc_items).

    toc_items is a list of {level, id, title} dicts for the sidebar.
    """
    md = markdown.Markdown(
        extensions=[
            "extra",        # tables, fenced_code, def_list, attr_list, footnotes
            "toc",          # automatic ID slugs + [TOC] marker
            "sane_lists",   # list parsing closer to CommonMark
            "smarty",       # smart quotes + em-dashes
        ],
        extension_configs={
            "toc": {
                "permalink": False,
                "anchorlink": False,
            }
        },
    )
    body = md.convert(text)

    # Extract TOC from the rendered HTML — we only want H2 and H3 in the sidebar
    # (the H1 is the title, the H4/H5 would clutter)
    toc_items = []
    for m in re.finditer(
        r'<(h2|h3)\s+id="([^"]+)">(.*?)</\1>', body, flags=re.DOTALL
    ):
        level = int(m.group(1)[1])
        anchor = m.group(2)
        # Strip any nested HTML tags from the title for the sidebar
        title = re.sub(r"<[^>]+>", "", m.group(3)).strip()
        toc_items.append({"level": level, "id": anchor, "title": title})

    return body, toc_items


# ============================================================================
# Post-processing the body HTML
# ============================================================================

def add_drop_cap_to_sections(body: str) -> str:
    """Wrap the first letter of each section's first paragraph in a drop-cap span.

    A "section" here is the content immediately following an <h2>.
    """
    # Match each <h2>...</h2> followed by an optional <h3> + <p>; we only
    # decorate the FIRST <p> in the section.
    def replace(match: re.Match) -> str:
        heading = match.group(1)
        rest = match.group(2)
        # Find the first <p> tag after the heading (skipping any leading whitespace)
        para_match = re.match(r"^(\s*)<p>([^\s<])(.*?)</p>", rest, flags=re.DOTALL)
        if not para_match:
            return match.group(0)
        ws, first_char, rest_of_para = para_match.groups()
        new_para = f'{ws}<p class="lede"><span class="dropcap">{first_char}</span>{rest_of_para}</p>'
        return heading + new_para + rest[para_match.end():]

    # The split point is the next <h2> or end of string; we capture each
    # h2-bounded section.
    parts = re.split(r"(<h2\s+id=\"[^\"]+\">.*?</h2>)", body, flags=re.DOTALL)
    rebuilt = []
    i = 0
    while i < len(parts):
        if i + 1 < len(parts) and parts[i + 1].startswith("<h2"):
            rebuilt.append(parts[i])
            i += 1
        else:
            rebuilt.append(parts[i])
            i += 1
    # Simpler: rejoin everything then apply per-section regex
    out = body
    # For each H2, find the first <p> within its section and add dropcap class
    sections = re.split(r"(?=<h2\s+id=)", body)
    new_sections = []
    for sec in sections:
        # Skip if the section doesn't start with h2 (the lead text before any h2)
        if not sec.startswith("<h2"):
            new_sections.append(sec)
            continue
        # Replace the FIRST <p>...</p> in this section
        sec_new = re.sub(
            r"<p>(\S)(.*?)</p>",
            lambda m: f'<p class="lede"><span class="dropcap">{m.group(1)}</span>{m.group(2)}</p>',
            sec, count=1, flags=re.DOTALL,
        )
        new_sections.append(sec_new)
    return "".join(new_sections)


def wrap_section_numbers(body: str) -> str:
    """Add a typographic § marker before each section number in H2 text.

    The markdown source has '## 1. Ambition' etc.; rendered as '<h2 id="...">1. Ambition</h2>'.
    We transform the leading '1.' into '<span class="hash">§ 01</span>'.
    """
    def replace(m: re.Match) -> str:
        anchor = m.group(1)
        num = m.group(2)
        rest = m.group(3)
        # Zero-pad
        padded = num.zfill(2)
        return (
            f'<h2 id="{anchor}">'
            f'<span class="hash">§&nbsp;{padded}</span>'
            f'<span class="htext">{rest}</span>'
            f'</h2>'
        )
    return re.sub(
        r'<h2\s+id="([^"]+)">(\d+)\.\s*(.*?)</h2>',
        replace,
        body, flags=re.DOTALL,
    )


def compute_reading_time(text: str) -> int:
    """Return reading time in minutes at ~200 words/min."""
    words = len(re.findall(r"\w+", text))
    return max(1, round(words / 200))


def strip_first_h1_and_meta(body: str) -> tuple[str, str, str]:
    """Pull the document title (first <h1>) and the immediately-following
    italic byline lines out of the body — we render them in our cover layout.
    Returns (cleaned_body, title, byline_lines_joined).
    """
    h1 = re.search(r"<h1>(.*?)</h1>", body)
    title = h1.group(1) if h1 else "Kern Whitepaper"

    # Remove the H1
    body = re.sub(r"<h1>.*?</h1>\s*", "", body, count=1)

    # Collect the leading <p><em>...</em></p> blocks (the byline + version + license)
    byline_parts = []
    while True:
        m = re.match(r"\s*<p><em>(.*?)</em></p>\s*", body, flags=re.DOTALL)
        if not m:
            break
        byline_parts.append(m.group(1))
        body = body[m.end():]

    # Remove a leading <hr/> after byline (Markdown's --- separator)
    body = re.sub(r"^\s*<hr\s*/?>\s*", "", body)

    byline = " · ".join(byline_parts) if byline_parts else ""
    return body, title, byline


def remove_inline_table_of_contents(body: str) -> str:
    """The markdown source includes its own '### Table of contents' section
    right inside the Abstract; we render the sidebar TOC instead, so strip
    the inline numbered list to avoid duplication."""
    # Find the H3 'Table of contents' and remove from that point through the
    # next <hr/> or next H2.
    pattern = re.compile(
        r'<h3[^>]*>Table of contents</h3>.*?(?=<hr\s*/?>|<h2)',
        flags=re.DOTALL | re.IGNORECASE,
    )
    return pattern.sub("", body)


# ============================================================================
# Sidebar TOC HTML
# ============================================================================

def render_sidebar_toc(toc: list[dict]) -> str:
    """Render the sidebar TOC as nested HTML.
    H2 entries are top-level; H3 entries nest under the most recent H2.
    """
    out = ['<nav class="toc" aria-label="Whitepaper sections">']
    out.append('<div class="toc-title">Contents</div>')
    out.append('<ol class="toc-list">')
    in_subgroup = False
    for item in toc:
        if item["level"] == 2:
            if in_subgroup:
                out.append("</ol></li>")
                in_subgroup = False
            # Strip leading "N." if present — we'll display the number separately
            title = item["title"]
            num_match = re.match(r"^(\d+)\.\s*(.*)$", title)
            if num_match:
                num = num_match.group(1).zfill(2)
                clean_title = num_match.group(2)
                out.append(
                    f'<li class="toc-h2">'
                    f'<a href="#{item["id"]}" data-anchor="{item["id"]}">'
                    f'<span class="toc-num">{num}</span>'
                    f'<span class="toc-text">{clean_title}</span>'
                    f'</a>'
                )
            else:
                # Abstract or other unnumbered
                out.append(
                    f'<li class="toc-h2 toc-unnumbered">'
                    f'<a href="#{item["id"]}" data-anchor="{item["id"]}">'
                    f'<span class="toc-text">{title}</span>'
                    f'</a>'
                )
            # Open a sub-list in case H3s follow
            out.append('<ol class="toc-sublist">')
            in_subgroup = True
        elif item["level"] == 3 and in_subgroup:
            # H3 subsections
            title = item["title"]
            out.append(
                f'<li class="toc-h3"><a href="#{item["id"]}" data-anchor="{item["id"]}">{title}</a></li>'
            )
    if in_subgroup:
        out.append("</ol></li>")
    out.append("</ol>")
    out.append("</nav>")
    return "".join(out)


# ============================================================================
# Page template
# ============================================================================

PAGE_TEMPLATE = """<!--
  SPDX-License-Identifier: Apache-2.0
  Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors

  Kern — whitepaper, rendered from docs/whitepaper.md.
  Regenerate with: python3 build_whitepaper.py
-->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — Whitepaper</title>
  <meta name="description" content="Whitepaper for Kern, a Layer-1 blockchain protocol for institutional legibility. Nicolas Van Eeckhout (founder) and contributors.">
  <meta name="author" content="Nicolas Van Eeckhout">

  <meta property="og:title" content="{title} — Kern Whitepaper">
  <meta property="og:description" content="The full whitepaper for Kern: thesis, primitives, verticals, roadmap.">
  <meta property="og:type" content="article">

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,300..900,0..100,0..1&family=Instrument+Sans:ital,wght@0,400..700;1,400..700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

  <style>
    /* ===================================================================
       Design tokens — Nordic editorial (shared with index.html)
       =================================================================== */
    :root {{
      --bg-paper: #FAFAF7;
      --bg-elevated: #FFFFFF;
      --bg-deep: #0E1A2B;
      --ink-primary: #0E1A2B;
      --ink-secondary: #3D4A5E;
      --ink-muted: #7A8595;
      --ink-faint: #B5BDC9;
      --ink-inverse: #FAFAF7;
      --rule: #E5E1D8;
      --rule-strong: #C9C3B5;
      --amber: #C2885E;
      --amber-deep: #8E5E3A;
      --bifrost: #1E3A8A;
      --moss: #5C7553;
      --rust: #A24E3C;

      --font-display: "Fraunces", "Iowan Old Style", Georgia, serif;
      --font-body:    "Instrument Sans", "Söhne", "Helvetica Neue", system-ui, sans-serif;
      --font-mono:    "JetBrains Mono", ui-monospace, SFMono-Regular, monospace;
    }}

    *, *::before, *::after {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      font-family: var(--font-display);
      font-size: 1.0625rem;          /* 17px body for long-form */
      line-height: 1.7;
      color: var(--ink-primary);
      background: var(--bg-paper);
      font-variation-settings: "opsz" 18, "SOFT" 50;
      font-feature-settings: "kern", "liga", "calt";
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      background-image:
        radial-gradient(at 90% 0%, rgba(194, 136, 94, 0.035) 0%, transparent 60%),
        radial-gradient(at 0% 100%, rgba(30, 58, 138, 0.02) 0%, transparent 50%);
      background-attachment: fixed;
    }}

    ::selection {{ background: var(--ink-primary); color: var(--bg-paper); }}
    a {{ color: inherit; }}

    .skip-link {{
      position: absolute; left: -9999px; top: 0;
      background: var(--ink-primary); color: var(--ink-inverse);
      padding: 0.5rem 1rem; z-index: 100;
    }}
    .skip-link:focus {{ left: 1rem; top: 1rem; }}

    /* Scroll progress bar */
    .progress {{
      position: fixed;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: transparent;
      z-index: 60;
      pointer-events: none;
    }}
    .progress-bar {{
      height: 100%;
      background: linear-gradient(to right, var(--amber), var(--amber-deep));
      width: 0;
      transition: width 0.05s linear;
    }}

    /* ===================================================================
       Header
       =================================================================== */
    .site-header {{
      position: sticky; top: 0; z-index: 50;
      background: rgba(250, 250, 247, 0.92);
      backdrop-filter: saturate(180%) blur(12px);
      -webkit-backdrop-filter: saturate(180%) blur(12px);
      border-bottom: 1px solid var(--rule);
    }}
    .header-inner {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 0.85rem 1.5rem;
      display: flex; align-items: center; justify-content: space-between;
      gap: 1.5rem;
    }}
    .brand {{
      display: flex; align-items: baseline; gap: 0.55rem;
      font-family: var(--font-display);
      font-size: 1.35rem;
      letter-spacing: -0.02em;
      font-variation-settings: "opsz" 144;
      text-decoration: none;
      color: var(--ink-primary);
    }}
    .brand .rune {{
      font-family: "Noto Sans Runic", "Segoe UI Historic", var(--font-display);
      font-size: 1.4em; color: var(--amber); transform: translateY(2px);
    }}
    .brand .where {{
      font-family: var(--font-mono);
      font-size: 0.6875rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--ink-muted);
      margin-left: 0.6rem;
    }}
    .header-nav {{
      display: flex; gap: 1.25rem; align-items: center;
      font-family: var(--font-body);
      font-size: 0.875rem;
      color: var(--ink-secondary);
    }}
    .header-nav a {{ text-decoration: none; transition: color 0.18s; }}
    .header-nav a:hover {{ color: var(--ink-primary); }}
    .header-actions {{ display: flex; gap: 0.6rem; align-items: center; }}
    .btn-ghost, .btn-primary {{
      display: inline-flex; align-items: center; gap: 0.35rem;
      padding: 0.5rem 1rem;
      border-radius: 999px;
      font-family: var(--font-body);
      font-size: 0.8125rem;
      font-weight: 500;
      text-decoration: none;
      transition: all 0.18s;
    }}
    .btn-ghost {{
      color: var(--ink-secondary);
      border: 1px solid var(--rule-strong);
      background: transparent;
    }}
    .btn-ghost:hover {{ color: var(--ink-primary); border-color: var(--ink-primary); }}
    .btn-primary {{
      background: var(--ink-primary); color: var(--ink-inverse);
      border: 1px solid var(--ink-primary);
    }}
    .btn-primary:hover {{ background: var(--amber-deep); border-color: var(--amber-deep); }}

    /* ===================================================================
       Layout: cover + (sidebar + article)
       =================================================================== */
    .cover {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 6rem 1.5rem 4rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .cover::before {{
      content: "ᚴ";
      position: absolute;
      top: 25%;
      left: 50%;
      transform: translate(-50%, 0);
      font-family: "Noto Sans Runic", "Segoe UI Historic", var(--font-display);
      font-size: clamp(18rem, 30vw, 26rem);
      color: var(--amber);
      opacity: 0.04;
      line-height: 1;
      pointer-events: none;
      user-select: none;
      z-index: 0;
    }}
    .cover > * {{ position: relative; z-index: 1; }}
    .cover-eyebrow {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--ink-muted);
      margin: 0 0 1.75rem;
    }}
    .cover-eyebrow span {{ color: var(--amber-deep); }}
    .cover h1 {{
      font-family: var(--font-display);
      font-size: clamp(2.5rem, 6vw, 5rem);
      line-height: 1.05;
      letter-spacing: -0.035em;
      font-weight: 350;
      font-variation-settings: "opsz" 144, "SOFT" 60, "WONK" 1;
      margin: 0 auto;
      max-width: 18ch;
    }}
    .cover h1 em {{
      font-style: italic;
      font-variation-settings: "opsz" 144, "SOFT" 100, "WONK" 1;
      color: var(--amber-deep);
    }}
    .cover-byline {{
      font-family: var(--font-display);
      font-style: italic;
      font-size: 1rem;
      color: var(--ink-muted);
      margin: 2rem 0 0;
      font-variation-settings: "opsz" 30, "SOFT" 80, "WONK" 1;
    }}
    .cover-meta {{
      margin: 3rem 0 0;
      display: flex;
      justify-content: center;
      gap: 2rem;
      flex-wrap: wrap;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      letter-spacing: 0.04em;
      color: var(--ink-muted);
    }}
    .cover-meta .meta-item {{
      display: flex; flex-direction: column; align-items: center; gap: 0.25rem;
    }}
    .cover-meta .meta-label {{
      font-size: 0.625rem;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--ink-faint);
    }}
    .cover-meta .meta-value {{
      font-family: var(--font-display);
      font-size: 1.125rem;
      color: var(--ink-primary);
      font-variation-settings: "opsz" 30;
      font-feature-settings: "tnum";
    }}
    .cover-rule {{
      width: 60px;
      height: 1px;
      background: var(--ink-primary);
      margin: 3rem auto 0;
    }}

    /* Two-column layout */
    .layout {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 0 1.5rem 6rem;
      display: grid;
      grid-template-columns: 1fr;
      gap: 3rem;
    }}
    @media (min-width: 980px) {{
      .layout {{
        grid-template-columns: 260px 1fr;
        gap: 5rem;
      }}
    }}

    /* ===================================================================
       Sidebar TOC
       =================================================================== */
    .sidebar {{
      position: relative;
    }}
    @media (min-width: 980px) {{
      .sidebar {{
        position: sticky;
        top: 5rem;
        height: calc(100vh - 7rem);
        overflow-y: auto;
        padding-right: 0.5rem;
        scrollbar-width: thin;
        scrollbar-color: var(--rule-strong) transparent;
      }}
      .sidebar::-webkit-scrollbar {{ width: 6px; }}
      .sidebar::-webkit-scrollbar-thumb {{ background: var(--rule-strong); border-radius: 3px; }}
    }}
    .toc-title {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--ink-muted);
      margin-bottom: 1rem;
      padding-bottom: 0.6rem;
      border-bottom: 1px solid var(--rule);
    }}
    .toc-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      counter-reset: toc-h2;
    }}
    .toc-list .toc-h2 {{
      margin-bottom: 0.4rem;
    }}
    .toc-list .toc-h2 > a {{
      display: grid;
      grid-template-columns: 1.75rem 1fr;
      gap: 0.4rem;
      align-items: baseline;
      padding: 0.35rem 0;
      font-family: var(--font-body);
      font-size: 0.875rem;
      color: var(--ink-secondary);
      text-decoration: none;
      line-height: 1.35;
      transition: color 0.15s;
      border-left: 2px solid transparent;
      padding-left: 0.5rem;
      margin-left: -0.5rem;
    }}
    .toc-list .toc-h2 > a:hover {{
      color: var(--ink-primary);
    }}
    .toc-list .toc-h2.is-current > a {{
      color: var(--ink-primary);
      border-left-color: var(--amber);
    }}
    .toc-list .toc-h2.is-current .toc-num {{
      color: var(--amber-deep);
    }}
    .toc-num {{
      font-family: var(--font-mono);
      font-size: 0.6875rem;
      color: var(--ink-muted);
      font-feature-settings: "tnum";
    }}
    .toc-list .toc-h2.toc-unnumbered > a {{
      grid-template-columns: 1fr;
    }}
    .toc-sublist {{
      list-style: none;
      padding: 0 0 0.25rem 2.25rem;
      margin: 0 0 0.5rem;
      font-family: var(--font-body);
      font-size: 0.8125rem;
    }}
    .toc-sublist li {{
      margin: 0.15rem 0;
    }}
    .toc-sublist a {{
      color: var(--ink-muted);
      text-decoration: none;
      padding: 0.15rem 0;
      display: block;
      transition: color 0.15s;
    }}
    .toc-sublist a:hover {{
      color: var(--ink-secondary);
    }}
    .toc-sublist a.is-current {{
      color: var(--amber-deep);
    }}

    /* ===================================================================
       Article — long-form typography
       =================================================================== */
    .article {{
      max-width: 660px;
      font-family: var(--font-display);
      font-size: 1.0625rem;
      line-height: 1.72;
      color: var(--ink-primary);
      font-variation-settings: "opsz" 18, "SOFT" 50;
    }}
    .article p, .article ul, .article ol, .article blockquote {{
      margin: 0 0 1.5rem;
    }}
    .article ul, .article ol {{ padding-left: 1.5rem; }}
    .article li {{ margin-bottom: 0.4rem; }}
    .article li::marker {{ color: var(--amber); }}

    /* H2 — major section markers with hanging § number */
    .article h2 {{
      font-family: var(--font-display);
      font-size: 2.25rem;
      line-height: 1.1;
      letter-spacing: -0.025em;
      font-weight: 350;
      font-variation-settings: "opsz" 144, "SOFT" 60, "WONK" 1;
      margin: 5rem 0 1.75rem;
      padding-top: 3rem;
      border-top: 1px solid var(--rule);
      color: var(--ink-primary);
      display: grid;
      grid-template-columns: 1fr;
      gap: 0.5rem;
    }}
    @media (min-width: 760px) {{
      .article h2 {{
        grid-template-columns: 1fr;
      }}
    }}
    .article h2 .hash {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.18em;
      color: var(--amber);
      font-weight: 500;
      text-transform: uppercase;
      align-self: start;
      margin-bottom: 0.2rem;
      display: block;
    }}
    .article h2 .htext {{
      display: block;
    }}
    /* The Abstract H2 (unnumbered) */
    .article > h2:first-of-type {{
      margin-top: 0;
      padding-top: 0;
      border-top: 0;
    }}

    .article h3 {{
      font-family: var(--font-display);
      font-size: 1.375rem;
      line-height: 1.3;
      letter-spacing: -0.015em;
      font-weight: 400;
      font-variation-settings: "opsz" 144, "SOFT" 30;
      margin: 2.5rem 0 1rem;
      color: var(--ink-primary);
    }}
    .article h4 {{
      font-family: var(--font-body);
      font-size: 0.875rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      font-weight: 600;
      color: var(--ink-secondary);
      margin: 2rem 0 0.75rem;
    }}

    /* Drop cap on the first paragraph of each section */
    .article .lede {{
      font-size: 1.1875rem;
      line-height: 1.65;
      color: var(--ink-primary);
    }}
    .article .dropcap {{
      float: left;
      font-family: var(--font-display);
      font-size: 4.5rem;
      line-height: 0.85;
      padding: 0.4rem 0.65rem 0 0;
      margin-top: 0.15rem;
      color: var(--amber-deep);
      font-variation-settings: "opsz" 144, "SOFT" 100, "WONK" 1;
      font-weight: 400;
    }}

    /* Strong + em + inline code */
    .article strong {{
      font-weight: 600;
      color: var(--ink-primary);
    }}
    .article em {{
      font-style: italic;
      font-variation-settings: "opsz" 18, "SOFT" 100, "WONK" 1;
    }}
    .article code {{
      font-family: var(--font-mono);
      font-size: 0.875em;
      background: rgba(194, 136, 94, 0.08);
      padding: 0.1em 0.35em;
      border-radius: 3px;
      color: var(--amber-deep);
    }}

    /* Code blocks */
    .article pre {{
      font-family: var(--font-mono);
      font-size: 0.8125rem;
      line-height: 1.55;
      background: var(--bg-deep);
      color: var(--ink-inverse);
      padding: 1.25rem 1.5rem;
      border-radius: 4px;
      overflow-x: auto;
      margin: 1.75rem 0;
      border-left: 3px solid var(--amber);
    }}
    .article pre code {{
      background: transparent;
      color: inherit;
      padding: 0;
    }}

    /* Blockquotes — used as pull-style asides in the original markdown */
    .article blockquote {{
      border-left: 2px solid var(--amber);
      padding: 0.25rem 0 0.25rem 1.5rem;
      margin: 1.75rem 0;
      font-style: italic;
      color: var(--ink-secondary);
      font-variation-settings: "opsz" 18, "SOFT" 100, "WONK" 1;
    }}
    .article blockquote p {{ margin-bottom: 0.6rem; }}
    .article blockquote p:last-child {{ margin-bottom: 0; }}

    /* Tables — keep them legible at narrow widths */
    .article table {{
      width: 100%;
      border-collapse: collapse;
      margin: 2rem 0;
      font-family: var(--font-body);
      font-size: 0.875rem;
      display: block;
      overflow-x: auto;
    }}
    .article table thead {{
      border-bottom: 2px solid var(--ink-primary);
    }}
    .article table th {{
      text-align: left;
      padding: 0.75rem 0.85rem;
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--ink-muted);
      font-weight: 500;
    }}
    .article table td {{
      padding: 0.9rem 0.85rem;
      border-bottom: 1px solid var(--rule);
      color: var(--ink-secondary);
      vertical-align: top;
      line-height: 1.5;
    }}
    .article table tbody tr:last-child td {{ border-bottom: 0; }}

    /* Links */
    .article a {{
      color: var(--amber-deep);
      text-decoration: none;
      border-bottom: 1px solid rgba(194, 136, 94, 0.4);
      transition: border-color 0.15s, color 0.15s;
    }}
    .article a:hover {{
      color: var(--ink-primary);
      border-bottom-color: var(--ink-primary);
    }}

    /* Horizontal rules from the markdown source */
    .article hr {{
      border: 0;
      height: 1px;
      background: var(--rule);
      margin: 4rem auto;
      width: 60%;
    }}

    /* The TOC inside the markdown body — we have a sidebar so de-emphasize */
    .article .toc-h3-inline {{ display: none; }}

    /* Footnotes (from markdown extra) */
    .article .footnote {{
      font-size: 0.875rem;
      color: var(--ink-muted);
      padding-top: 2rem;
      margin-top: 4rem;
      border-top: 1px solid var(--rule);
    }}

    /* ===================================================================
       Footer
       =================================================================== */
    .site-footer {{
      background: var(--bg-deep);
      color: var(--ink-inverse);
      padding: 3rem 0 1.5rem;
      margin-top: 5rem;
    }}
    .footer-inner {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 0 1.5rem;
    }}
    .footer-grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 2.5rem;
      margin-bottom: 2.5rem;
    }}
    @media (min-width: 760px) {{
      .footer-grid {{ grid-template-columns: 2fr 1fr 1fr; }}
    }}
    .footer-brand {{
      font-family: var(--font-display);
      font-size: 1.5rem;
      margin-bottom: 0.75rem;
      font-variation-settings: "opsz" 144;
    }}
    .footer-brand .rune {{ color: var(--amber); font-family: "Noto Sans Runic", "Segoe UI Historic", var(--font-display); }}
    .footer-tagline {{
      font-family: var(--font-display);
      font-style: italic;
      color: rgba(250, 250, 247, 0.55);
      font-size: 0.9375rem;
      line-height: 1.5;
      max-width: 36ch;
      font-variation-settings: "opsz" 30, "SOFT" 80, "WONK" 1;
      margin: 0;
    }}
    .footer-grid h5 {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: rgba(250, 250, 247, 0.5);
      margin: 0 0 1rem;
      font-weight: 500;
    }}
    .footer-grid ul {{
      list-style: none; padding: 0; margin: 0;
      display: flex; flex-direction: column; gap: 0.5rem;
      font-size: 0.875rem;
    }}
    .footer-grid a {{
      color: rgba(250, 250, 247, 0.75);
      text-decoration: none;
      transition: color 0.18s;
    }}
    .footer-grid a:hover {{ color: var(--ink-inverse); }}
    .footer-bottom {{
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      padding-top: 1.25rem;
      display: flex; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--font-mono);
      font-size: 0.7rem;
      color: rgba(250, 250, 247, 0.4);
      letter-spacing: 0.04em;
    }}

    /* ===================================================================
       Print stylesheet — give institutions a clean PDF
       =================================================================== */
    @media print {{
      .site-header, .sidebar, .progress, .site-footer {{ display: none !important; }}
      body {{ background: white; color: black; font-size: 11pt; }}
      .cover {{ padding: 2rem 0; }}
      .cover::before {{ display: none; }}
      .layout {{ display: block; padding: 0; max-width: none; }}
      .article {{ max-width: none; font-size: 11pt; line-height: 1.45; }}
      .article h2 {{ break-before: page; margin-top: 0; }}
      .article a {{ color: black; border-bottom: 0; }}
      .article a[href^="http"]::after {{ content: " (" attr(href) ")"; font-size: 0.85em; color: #555; }}
      .article pre {{ background: #f4f4f4; color: black; border-left-color: #999; }}
      .article code {{ background: #f4f4f4; color: black; }}
    }}

    /* Reduced motion */
    @media (prefers-reduced-motion: reduce) {{
      html {{ scroll-behavior: auto; }}
    }}
  </style>
  <link rel="icon" type="image/svg+xml" href="favicon.svg" media="(prefers-color-scheme: light)">
  <link rel="icon" type="image/svg+xml" href="favicon-dark.svg" media="(prefers-color-scheme: dark)">
  <link rel="icon" type="image/svg+xml" href="favicon.svg">
  <link rel="apple-touch-icon" href="apple-touch-icon.svg">
  <meta name="theme-color" content="#FAFAF7" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0E1A2B" media="(prefers-color-scheme: dark)">
</head>
<body>

<a href="#article" class="skip-link">Skip to whitepaper content</a>

<div class="progress" aria-hidden="true"><div class="progress-bar" id="progress-bar"></div></div>

<header class="site-header">
  <div class="header-inner">
    <a href="index.html" class="brand">
      <span class="rune" aria-hidden="true">ᚴ</span>
      <span>Kern</span>
      <span class="where">whitepaper</span>
    </a>
    <nav class="header-nav" aria-label="Section quick access">
      <a href="how-it-works.html">How it works</a>
      <a href="use-cases.html">Use cases</a>
      <a href="#abstract">Abstract</a>
      <a href="#4-the-core-thesis-institutional-legibility">Thesis</a>
      <a href="#11-token-economy">Economy</a>
      <a href="#14-v12-roadmap">Roadmap</a>
      <a href="glossary.html">Glossary</a>
    </nav>
    <div class="header-actions">
      <button class="btn-ghost" onclick="window.print()" title="Print or save as PDF">Print / PDF</button>
      <a href="https://www.linkedin.com/in/vaneeckhout/" class="btn-primary" target="_blank" rel="noopener">Follow on LinkedIn →</a>
    </div>
  </div>
</header>

<main>
<!-- ====================================================================
     COVER
     ==================================================================== -->
<section class="cover">
  <p class="cover-eyebrow">Whitepaper · <span>v1.1 release candidate</span> · {date}</p>
  <h1>{title_html}</h1>
  <p class="cover-byline">{byline}</p>
  <div class="cover-meta">
    <div class="meta-item">
      <span class="meta-label">Sections</span>
      <span class="meta-value">{n_sections}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Reading</span>
      <span class="meta-value">~{reading_time} min</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Words</span>
      <span class="meta-value">{word_count_str}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">License</span>
      <span class="meta-value mono" style="font-family: var(--font-mono); font-size: 0.875rem;">CC-BY-SA-4.0</span>
    </div>
  </div>
  <div class="cover-rule"></div>
</section>

<!-- ====================================================================
     TWO-COLUMN: SIDEBAR + ARTICLE
     ==================================================================== -->
<div class="layout">
  <aside class="sidebar">
    {sidebar_toc}
  </aside>
  <article id="article" class="article">
    {body}
  </article>
</div>
</main>

<footer class="site-footer">
  <div class="footer-inner">
    <div class="footer-grid">
      <div>
        <div class="footer-brand">
          <span class="rune" aria-hidden="true">ᚴ</span> Kern
        </div>
        <p class="footer-tagline">
          The kernel. The grain of state that endures. Read the whitepaper, then read the source.
        </p>
      </div>
      <div>
        <h5>Read</h5>
        <ul>
          <li><a href="index.html">Landing page</a></li>
          <li><a href="#abstract">Abstract</a></li>
          <li><a href="#16-reference-implementation">Reference impl</a></li>
        </ul>
      </div>
      <div>
        <h5>Source</h5>
        <ul>
          <li><a href="https://github.com/vaneeckhoutnicolas/kern" target="_blank" rel="noopener">GitHub</a></li>
          <li><a href="github.html#docs">Setup guides</a></li>
          <li><a href="index.html#heimdall">Heimdall explorer</a></li>
          <li><a href="https://www.linkedin.com/in/vaneeckhout/" target="_blank" rel="noopener">Follow on LinkedIn</a></li>
        </ul>
      </div>
    </div>
    <div class="footer-bottom">
      <span>© 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors</span>
      <span>Whitepaper: CC-BY-SA-4.0 · Reference impl: Apache-2.0 · <a href="https://github.com/vaneeckhoutnicolas/kern/blob/main/docs/disclaimer.md" target="_blank" rel="noopener" style="color:inherit;border-bottom:1px solid rgba(255,255,255,0.2);">Disclaimer</a></span>
    </div>
  </div>
</footer>

<script>
// Scroll progress bar
(function () {{
  const bar = document.getElementById('progress-bar');
  if (!bar) return;
  const update = () => {{
    const h = document.documentElement;
    const max = h.scrollHeight - h.clientHeight;
    const pct = max > 0 ? (h.scrollTop / max) * 100 : 0;
    bar.style.width = pct + '%';
  }};
  window.addEventListener('scroll', update, {{ passive: true }});
  window.addEventListener('resize', update);
  update();
}})();

// Sidebar TOC: highlight the current section based on scroll position
(function () {{
  const headings = Array.from(document.querySelectorAll('.article h2[id], .article h3[id]'));
  if (!headings.length) return;
  const tocLinks = Array.from(document.querySelectorAll('.toc a[data-anchor]'));
  const linkByAnchor = new Map(tocLinks.map(a => [a.dataset.anchor, a]));
  let currentAnchor = null;

  const setCurrent = (anchor) => {{
    if (anchor === currentAnchor) return;
    if (currentAnchor) {{
      const prev = linkByAnchor.get(currentAnchor);
      if (prev) {{
        prev.classList.remove('is-current');
        const parentLi = prev.closest('li.toc-h2');
        if (parentLi) parentLi.classList.remove('is-current');
      }}
    }}
    currentAnchor = anchor;
    const cur = linkByAnchor.get(anchor);
    if (cur) {{
      cur.classList.add('is-current');
      const parentLi = cur.closest('li.toc-h2');
      if (parentLi) parentLi.classList.add('is-current');
    }}
  }};

  // Use IntersectionObserver to track which heading is currently near the top
  const io = new IntersectionObserver((entries) => {{
    // Find the topmost visible heading
    const visible = entries.filter(e => e.isIntersecting)
      .map(e => e.target)
      .sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top);
    if (visible.length) {{
      setCurrent(visible[0].id);
    }} else {{
      // Fall back: pick the last heading that is above the viewport top
      const above = headings.filter(h => h.getBoundingClientRect().top < 120);
      if (above.length) setCurrent(above[above.length - 1].id);
    }}
  }}, {{
    rootMargin: '-100px 0px -65% 0px',
    threshold: [0, 1.0],
  }});
  headings.forEach(h => io.observe(h));
}})();
</script>

</body>
</html>
"""


# ============================================================================
# Driver
# ============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", default=str(DEFAULT_SOURCE),
                    help=f"path to whitepaper.md (default: {DEFAULT_SOURCE})")
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help=f"output HTML (default: {DEFAULT_OUT})")
    args = ap.parse_args()

    source = Path(args.source).resolve()
    out = Path(args.out).resolve()

    if not source.exists():
        print(f"ERROR: source not found: {source}", file=sys.stderr)
        return 1

    md_text = source.read_text(encoding="utf-8")
    word_count = len(re.findall(r"\w+", md_text))
    reading_time = compute_reading_time(md_text)

    body, toc_items = convert_markdown(md_text)

    # Strip the H1 + leading byline lines (we render them in the cover)
    body, title, byline = strip_first_h1_and_meta(body)

    # Remove the inline "Table of contents" — we have a sidebar
    body = remove_inline_table_of_contents(body)

    # Post-process: § numbering on H2, drop caps on lede paragraphs
    body = wrap_section_numbers(body)
    body = add_drop_cap_to_sections(body)

    # Filter TOC: drop H1 entries (the title) and the inline "Table of contents" heading
    toc_items = [t for t in toc_items
                 if not t["title"].lower().startswith("table of contents")]

    sidebar = render_sidebar_toc(toc_items)

    # Reformat title: italicize the part after "—" for elegance
    title_html = title
    if " — " in title:
        head, tail = title.split(" — ", 1)
        title_html = f'{head} <em>{tail}</em>'

    # Count H2 sections (excluding Abstract)
    n_sections = sum(1 for t in toc_items if t["level"] == 2)

    html = PAGE_TEMPLATE.format(
        title=title,
        title_html=title_html,
        byline=byline or "Nicolas Van Eeckhout · Kern contributors",
        date=datetime.now().strftime("%B %Y"),
        n_sections=n_sections,
        reading_time=reading_time,
        word_count_str=f"{word_count:,}".replace(",", " "),
        sidebar_toc=sidebar,
        body=body,
    )

    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size:,} bytes)")
    print(f"  sections: {n_sections}")
    print(f"  words:    {word_count:,}")
    print(f"  reading:  ~{reading_time} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
