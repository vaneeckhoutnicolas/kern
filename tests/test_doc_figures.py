# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Kern contributors
"""The figures and the explainer video shown by the documentation.

Every image a markdown document shows must exist, every figure must be
shown somewhere and carry a title and a description, and the white paper
page must publish its figures next to itself: the site deploys kern_site/,
not docs/, so a figure left in docs/ would be a broken image on the site.
"""

from __future__ import annotations

import importlib.util
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIGURES = ROOT / "docs" / "figures"
SITE = ROOT / "kern_site"
SVG_NS = "{http://www.w3.org/2000/svg}"

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")
HTML_IMG = re.compile(r"<img\b[^>]*\bsrc=\"([^\"]+)\"")
HTML_LINK = re.compile(r"<a\b[^>]*\bhref=\"([^\"]+)\"")


def _markdown_files() -> list[Path]:
    return [ROOT / "README.md"] + sorted((ROOT / "docs").rglob("*.md"))


def _local(ref: str) -> bool:
    return not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", ref) and not ref.startswith("#")


def _images(md: Path) -> list[str]:
    text = md.read_text(encoding="utf-8")
    return [r for r in MD_IMAGE.findall(text) + HTML_IMG.findall(text) if _local(r)]


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_whitepaper", SITE / "build_whitepaper.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_image_shown_by_a_document_exists():
    missing = []
    for md in _markdown_files():
        for ref in _images(md):
            if not (md.parent / ref.partition("#")[0]).resolve().is_file():
                missing.append(f"{md.relative_to(ROOT)}: {ref}")
    assert not missing, missing


def test_figures_exist_and_are_all_shown():
    svgs = sorted(FIGURES.glob("*.svg"))
    assert len(svgs) >= 7
    shown = {(md.parent / ref).resolve() for md in _markdown_files() for ref in _images(md)}
    orphans = [p.name for p in svgs if p.resolve() not in shown]
    assert not orphans, orphans


@pytest.mark.parametrize("svg", sorted(FIGURES.glob("*.svg")), ids=lambda p: p.name)
def test_figure_is_valid_svg_with_title_and_description(svg):
    root = ET.parse(svg).getroot()
    assert root.tag == SVG_NS + "svg"
    assert root.get("viewBox")
    title = root.find(SVG_NS + "title")
    desc = root.find(SVG_NS + "desc")
    assert title is not None and title.text and title.text.strip()
    assert desc is not None and desc.text and len(desc.text.strip()) > 80


def test_every_figure_has_a_caption_naming_its_file():
    """A figure is followed by an italic caption that names its source file."""
    for md in _markdown_files():
        text = md.read_text(encoding="utf-8")
        for m in MD_IMAGE.finditer(text):
            ref = m.group(1)
            if not ref.endswith(".svg"):
                continue
            after = text[m.end():m.end() + 200]
            name = Path(ref).name
            assert re.match(r"\s*\n\s*\*Figure \d+ \(`docs/figures/" + re.escape(name) + "`",
                            after), f"{md.relative_to(ROOT)}: no caption after {ref}"


VIDEO_URL = "https://github.com/user-attachments/assets/c5c4a092-de52-4082-a11a-9b4859b6a52c"


def test_readme_video_poster_and_file_exist():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    # The poster plays the copy uploaded to GitHub (a repository file only
    # downloads); the full quality file in the repository is linked too.
    poster = re.search(r"<a\b[^>]*\bhref=\"([^\"]+)\"[^>]*>\s*<img\b[^>]*kern-explainer-poster\.jpg",
                       text)
    assert poster, "the poster is a link"
    assert poster.group(1) == VIDEO_URL
    links = [h for h in HTML_LINK.findall(text) if h.endswith(".mp4")]
    assert links, "the README links to the full quality video"
    for href in links:
        assert (ROOT / href).is_file(), href
    assert (ROOT / "docs/figures/kern-explainer-poster.jpg").is_file()
    # The poster comes before the first section, so it is seen first.
    assert text.index("kern-explainer-poster.jpg") < text.index("\n## ")


def test_builder_copies_figures_next_to_the_page(tmp_path):
    mod = _load_builder()
    src = tmp_path / "docs" / "paper.md"
    (tmp_path / "docs" / "figures").mkdir(parents=True)
    (tmp_path / "docs" / "figures" / "a.svg").write_text("<svg/>", encoding="utf-8")
    src.write_text("x", encoding="utf-8")
    out_dir = tmp_path / "site"
    out_dir.mkdir()
    body = ('<p><img alt="A" src="figures/a.svg" /></p>'
            '<p><img src="https://example.org/b.svg"></p>')
    new, copied = mod.publish_figures(body, src, out_dir)
    assert (out_dir / "figures" / "a.svg").read_text(encoding="utf-8") == "<svg/>"
    assert copied == [out_dir / "figures" / "a.svg"]
    assert 'src="figures/a.svg"' in new
    assert 'src="https://example.org/b.svg"' in new


def test_builder_refuses_a_missing_image(tmp_path):
    mod = _load_builder()
    src = tmp_path / "paper.md"
    src.write_text("x", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        mod.publish_figures('<img alt="" src="figures/none.svg" />', src, tmp_path)


def test_drop_cap_never_takes_a_figure():
    mod = _load_builder()
    body = '<h2 id="s">1. S</h2><p><img alt="A" src="figures/a.svg" /></p><p>Text</p>'
    out = mod.add_drop_cap_to_sections(body)
    assert '<span class="dropcap"><' not in out
    assert '<span class="dropcap">T</span>' in out


def test_published_page_figures_match_the_sources():
    html = (SITE / "whitepaper.html").read_text(encoding="utf-8")
    srcs = HTML_IMG.findall(html)
    assert srcs, "the white paper page shows figures"
    for src in srcs:
        page_copy = SITE / src
        assert page_copy.is_file(), src
        assert page_copy.read_bytes() == (FIGURES / page_copy.name).read_bytes(), src
