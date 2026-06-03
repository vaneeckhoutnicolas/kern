# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v1.1-rc tokenized-securities Skald templates.

These tests verify that the three STO templates type-check successfully
under the Skald static type system. The templates encode the EU securities regime (Prospectus
Regulation, MiFID II, AIFMD, MAR) as Skald invariants — security tokens
are excluded from MiCA by Art. 2(4) — see
docs/sto-mica.md for the design rationale."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.skald.typecheck import type_check


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "kern" / "skald" / "examples"

STO_TEMPLATES = [
    "sto-startup-equity.skald",
    "sto-institutional-fund.skald",
    "sto-real-estate.skald",
]


@pytest.mark.parametrize("filename", STO_TEMPLATES)
def test_sto_template_typechecks(filename):
    """Each STO template must type-check successfully."""
    path = EXAMPLES_DIR / filename
    assert path.exists(), f"Template {filename} not found"
    source = path.read_text()
    errors = type_check(source)
    assert not errors, f"Type errors in {filename}: {errors[:3]}"


def test_startup_equity_has_securities_invariants():
    """The startup-equity template must declare prospectus + custody-segregation invariants."""
    source = (EXAMPLES_DIR / "sto-startup-equity.skald").read_text()
    # Check that the named invariants are present.
    assert "prospectus_whitepaper_before_issuance" in source
    assert "mifid_art16_custody_segregation" in source
    assert "mifid_art16_release_requires_authorization" in source


def test_institutional_fund_has_aifmd_invariants():
    """The institutional-fund template must encode AIFMD requirements."""
    source = (EXAMPLES_DIR / "sto-institutional-fund.skald").read_text()
    assert "aifmd_art21_depositary_independence" in source
    assert "aifmd_art18_concentration_limit" in source
    assert "prospectus_before_issuance" in source


def test_real_estate_has_title_invariant():
    """The real-estate template must require title registration before issuance."""
    source = (EXAMPLES_DIR / "sto-real-estate.skald").read_text()
    assert "title_registered_before_issuance" in source
    assert "prospectus_before_issuance" in source
    # Rental distribution bounded by collected rent (anti-Ponzi).
    assert "rental_distribution_bounded" in source


def test_all_stos_have_regulator_freeze():
    """Every STO must allow the regulator to freeze the contract (emergency stop)."""
    for filename in STO_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "regulator_freeze" in source, f"{filename} missing regulator_freeze entry"
        assert "regulator" in source, f"{filename} missing regulator role"


def test_all_stos_have_blackout_support():
    """MAR (market-abuse) — every STO must support blackout windows."""
    for filename in STO_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "blackout_active" in source, f"{filename} missing blackout_active"
        assert "start_blackout" in source, f"{filename} missing start_blackout"
        assert "end_blackout" in source, f"{filename} missing end_blackout"


def test_all_stos_have_compliance_oracle_role():
    """All templates rely on an off-chain compliance oracle for attestation reading."""
    for filename in STO_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "compliance_oracle" in source, f"{filename} missing compliance_oracle role"


def test_real_estate_requires_notary():
    """Real estate tokenization requires a notary role for title attestation."""
    source = (EXAMPLES_DIR / "sto-real-estate.skald").read_text()
    assert "notary" in source.lower()
    assert "title_registered" in source
    assert "title_attestation_hash" in source


def test_institutional_fund_requires_independent_depositary():
    """AIFMD Art. 21: depositary must be distinct from AIFM."""
    source = (EXAMPLES_DIR / "sto-institutional-fund.skald").read_text()
    assert "aifm != depositary" in source


def test_institutional_fund_has_nav_staleness_check():
    """AIFMD Art. 22: NAV staleness blocks redemptions."""
    source = (EXAMPLES_DIR / "sto-institutional-fund.skald").read_text()
    assert "nav_max_staleness_levels" in source
    assert "NAV too stale" in source


def test_real_estate_has_rental_distribution_bound():
    """Anti-Ponzi: distributions must be bounded by actual rent received."""
    source = (EXAMPLES_DIR / "sto-real-estate.skald").read_text()
    # Verify the invariant exists and that distributions cannot exceed received
    assert "rental_income_distributed <= rental_income_received" in source


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    # parametrize doesn't work in direct exec; run the explicit ones
    for name, obj in inspect.getmembers(me):
        if name.startswith("test_") and callable(obj):
            try:
                # Skip parametrize since it requires pytest
                if "parametrize" in str(getattr(obj, "pytestmark", [])):
                    for fn in STO_TEMPLATES:
                        obj(fn)
                else:
                    obj()
                print(f"  ✓ {name}")
            except Exception as e:
                print(f"  ✗ {name}: {e}")
