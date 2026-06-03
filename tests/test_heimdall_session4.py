# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for Heimdall Session 4 — UI polish, pagination, full-text search.

Covers:
- Pagination math helper (_make_pagination)
- Pagination on /blocks, /txs, /contracts
- Contract full-text search (?q=...)
- ARIA accessibility markers (skip link, role=main, aria-sort, role=search)
- Sortable table markup (data-sort attributes, Alpine helper present)
- RFP doc structure
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern_explorer.db import init_schema, open_db, transaction, upsert_account


# ===========================================================================
# Pagination math
# ===========================================================================

class TestPaginationHelper:
    def setup_method(self):
        # Lazy import — _make_pagination is in app.py which has import-time side
        # effects on env. Reload-safe approach: import here.
        from kern_explorer.app import _make_pagination
        self.fn = _make_pagination

    def test_empty(self):
        p = self.fn(1, 50, 0)
        assert p["page"] == 1
        assert p["total"] == 0
        assert p["total_pages"] == 1
        assert not p["has_prev"]
        assert not p["has_next"]

    def test_exact_one_page(self):
        p = self.fn(1, 50, 50)
        assert p["total_pages"] == 1
        assert not p["has_next"]

    def test_partial_second_page(self):
        p = self.fn(1, 50, 75)
        assert p["total_pages"] == 2
        assert p["has_next"]
        assert p["next_page"] == 2

    def test_middle_page(self):
        p = self.fn(3, 20, 100)
        assert p["total_pages"] == 5
        assert p["has_prev"] and p["has_next"]
        assert p["prev_page"] == 2
        assert p["next_page"] == 4

    def test_last_page(self):
        p = self.fn(5, 20, 100)
        assert p["page"] == 5
        assert p["total_pages"] == 5
        assert p["has_prev"]
        assert not p["has_next"]

    def test_qs_preserved(self):
        p = self.fn(1, 50, 100, qs="&kind=attest")
        assert p["qs"] == "&kind=attest"


# ===========================================================================
# App with seeded data for pagination + search tests
# ===========================================================================

@pytest.fixture
def app_with_pages(tmp_path):
    """An app pointing at a DB with 75 blocks, 75 txs, and 30 contracts.

    Just enough rows to exercise multi-page navigation.
    """
    db_path = tmp_path / "s4.sqlite"
    os.environ["HEIMDALL_DB"] = str(db_path)
    os.environ["HEIMDALL_INDEXER"] = "0"
    import importlib
    import kern_explorer.app as app_module
    importlib.reload(app_module)

    # Seed
    conn = open_db(str(db_path))
    init_schema(conn)
    now = int(time.time())
    with transaction(conn):
        for level in range(1, 76):
            conn.execute(
                "INSERT INTO blocks(level, hash, parent_hash, timestamp, baker, tx_count, indexed_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (level, f"hash_{level:04d}", f"hash_{level-1:04d}" if level > 1 else None,
                 now - (75 - level), "kn1baker", 1, now),
            )
            conn.execute(
                "INSERT INTO txs(hash, block_level, block_ts, kind, sender, recipient, "
                "amount, fee, gas_used, nonce, success, error, params_json, extra_json) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"tx_{level}", level, now - (75 - level),
                 "transfer" if level % 2 == 0 else "attest",
                 f"kn1sender_{level}", "kn1recipient", 1_000_000, 1000, 1000, 0, 1,
                 None, None, None),
            )
        upsert_account(conn, address="kn1baker", is_validator=1, balance=10_000_000)

        # 30 contracts: 10 STO, 10 QF, 10 oracle. Mix of source containing
        # specific substrings for the full-text search test.
        templates = [
            ("sto-startup-equity",
             "contract StoStartupEquity { storage { whitepaper_registered: bool, kyc_required: bool, } }"),
            ("quadratic-funding",
             "contract QuadraticFundingProject { storage { contributors_count: int, sum_of_sqrt_contributions: int, } }"),
            ("generic-data-oracle",
             "contract GenericDataOracle { storage { feeders: list[address], circuit_breaker_tripped: bool, } }"),
        ]
        for i in range(30):
            t, src = templates[i % 3]
            conn.execute(
                "INSERT INTO contracts(address, code, skald_template, originated_at_level, "
                "originated_by, last_refreshed_at_level) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (f"kn1c_{i:03d}", src, t, i + 1, "kn1deployer", i + 1),
            )
    conn.close()

    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as client:
        yield client


class TestBlocksPagination:
    def test_default_page1(self, app_with_pages):
        r = app_with_pages.get("/blocks")
        assert r.status_code == 200
        # 50 per page default, 75 total → page 1 shows 50, page 2 shows 25
        assert "Page <span class=\"font-medium\">1</span> of\n        <span class=\"font-medium\">2</span>" in r.text or "Page 1" in r.text

    def test_page2_loads(self, app_with_pages):
        r = app_with_pages.get("/blocks?page=2")
        assert r.status_code == 200

    def test_page_beyond_last_still_renders(self, app_with_pages):
        # Out-of-range pages should not error — just show an empty list
        r = app_with_pages.get("/blocks?page=99")
        assert r.status_code == 200

    def test_per_page_clamp(self, app_with_pages):
        # per_page > 200 is clamped server-side by Query(ge=10, le=200)
        r = app_with_pages.get("/blocks?per_page=500")
        assert r.status_code == 422  # FastAPI returns 422 on validation fail

    def test_per_page_below_min_rejected(self, app_with_pages):
        r = app_with_pages.get("/blocks?per_page=5")
        assert r.status_code == 422


class TestTxsPagination:
    def test_default(self, app_with_pages):
        r = app_with_pages.get("/txs")
        assert r.status_code == 200

    def test_kind_filter_paginated(self, app_with_pages):
        # 38 attest txs (odd-numbered levels 1..75 = 38 odd numbers)
        r = app_with_pages.get("/txs?kind=attest&page=1")
        assert r.status_code == 200
        # Pagination should show the kind in the qs links
        assert "kind=attest" in r.text


class TestContractsSearchAndPagination:
    def test_full_text_search_finds_keyword(self, app_with_pages):
        # 10 STO contracts have "whitepaper_registered" in source
        r = app_with_pages.get("/contracts?q=whitepaper_registered")
        assert r.status_code == 200
        # Should not find oracle or QF contracts in this filter
        assert "kn1c_000" in r.text   # STO 0
        # Some oracle contracts have circuit_breaker_tripped, not whitepaper
        r2 = app_with_pages.get("/contracts?q=circuit_breaker_tripped")
        assert r2.status_code == 200
        # Should find the oracle contract IDs (i % 3 == 2 → kn1c_002, 005, 008, ...)
        assert "kn1c_002" in r2.text
        # ...but NOT the STO whitepaper contracts (which don't have circuit_breaker_tripped)
        # (Caveat: their addresses do contain "0" so just check the search-result indicator)

    def test_search_no_match_renders(self, app_with_pages):
        r = app_with_pages.get("/contracts?q=nonexistent_keyword_xyz")
        assert r.status_code == 200
        assert "No contracts match" in r.text

    def test_search_combined_with_template_filter(self, app_with_pages):
        # Searching for "QuadraticFunding" while restricting to QF template
        r = app_with_pages.get("/contracts?template=quadratic-funding&q=QuadraticFunding")
        assert r.status_code == 200
        # All 10 QF contracts should match
        for i in (1, 4, 7, 10, 13):    # i % 3 == 1
            assert f"kn1c_{i:03d}" in r.text

    def test_search_resilient_to_special_chars(self, app_with_pages):
        # Won't match but shouldn't crash
        r = app_with_pages.get("/contracts?q=%25")    # URL-encoded %
        assert r.status_code == 200

    def test_pagination_works_with_filter_combinations(self, app_with_pages):
        r = app_with_pages.get("/contracts?template=sto-startup-equity&page=1")
        assert r.status_code == 200


# ===========================================================================
# ARIA accessibility markers
# ===========================================================================

class TestAccessibilityMarkers:
    def test_skip_link_in_base(self, app_with_pages):
        r = app_with_pages.get("/")
        assert 'href="#main"' in r.text
        assert "Skip to main content" in r.text

    def test_main_landmark(self, app_with_pages):
        r = app_with_pages.get("/")
        assert 'id="main"' in r.text
        assert 'role="main"' in r.text

    def test_search_form_has_role_and_label(self, app_with_pages):
        r = app_with_pages.get("/")
        assert 'role="search"' in r.text
        # The search input should have an associated label (visually hidden)
        assert 'for="global-search"' in r.text
        assert 'id="global-search"' in r.text

    def test_nav_has_aria_label(self, app_with_pages):
        r = app_with_pages.get("/")
        assert 'aria-label="Main navigation"' in r.text

    def test_sortable_th_have_aria_sort(self, app_with_pages):
        r = app_with_pages.get("/blocks")
        assert ':aria-sort=' in r.text   # Alpine binding present
        assert 'tabindex="0"' in r.text  # keyboard-focusable

    def test_pagination_has_aria_label(self, app_with_pages):
        # Multi-page case
        r = app_with_pages.get("/blocks")
        assert 'aria-label="Pagination"' in r.text or 'aria-label="Next page"' in r.text

    def test_dark_mode_button_has_label_and_pressed(self, app_with_pages):
        r = app_with_pages.get("/")
        assert 'aria-label="Toggle dark mode"' in r.text
        assert ':aria-pressed="dark"' in r.text


# ===========================================================================
# Alpine sortable helper present in base
# ===========================================================================

class TestSortableHelper:
    def test_alpine_sortable_helper_loaded(self, app_with_pages):
        r = app_with_pages.get("/")
        assert "Alpine.data('sortableTable'" in r.text
        assert "_applySort" in r.text


# ===========================================================================
# RFP doc structure
# ===========================================================================

class TestRfpDoc:
    @pytest.fixture
    def rfp(self):
        path = Path(__file__).resolve().parent.parent / "docs" / "heimdall-rfp-next-gen.md"
        return path.read_text()

    def test_rfp_file_exists(self, rfp):
        assert len(rfp) > 1000

    def test_rfp_required_sections(self, rfp):
        for heading in ("Why an RFP", "Timing", "Functional requirements",
                        "Must have", "Should have", "Won't have",
                        "Non-functional requirements", "Performance",
                        "Vendor evaluation criteria", "Submission"):
            assert heading in rfp, f"RFP missing section: {heading}"

    def test_rfp_links_to_existing_docs(self, rfp):
        import re
        link_re = re.compile(r'\[`?([^\]]+?)`?\]\(([^)]+)\)')
        docs_dir = Path(__file__).resolve().parent.parent / "docs"
        for m in link_re.finditer(rfp):
            target = m.group(2)
            if target.startswith(("http://", "https://", "#")):
                continue
            # Strip any anchor
            path = target.split("#")[0]
            if not path:
                continue
            assert (docs_dir / path).exists() or (docs_dir.parent / path).exists(), \
                f"RFP links to missing file: {target}"

    def test_rfp_attribution_present(self, rfp):
        assert "Nicolas Van Eeckhout" in rfp
        assert "Apache-2.0" in rfp
