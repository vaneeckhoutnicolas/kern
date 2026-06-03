# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v1.1-rc public goods funding Skald templates.

Verifies that the Quadratic Funding and Retroactive PGF templates
type-check successfully and encode the key design properties as
named invariants and structural roles."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.skald.typecheck import type_check


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "kern" / "skald" / "examples"

PGF_TEMPLATES = [
    "quadratic-funding.skald",
    "retroactive-pgf.skald",
]


@pytest.mark.parametrize("filename", PGF_TEMPLATES)
def test_pgf_template_typechecks(filename):
    """Each public goods funding template must type-check successfully."""
    path = EXAMPLES_DIR / filename
    assert path.exists(), f"Template {filename} not found"
    source = path.read_text()
    errors = type_check(source)
    assert not errors, f"Type errors in {filename}: {errors[:3]}"


# ---------------------------------------------------------------------------
# Quadratic Funding
# ---------------------------------------------------------------------------

def test_qf_has_two_step_contribution():
    """QF must separate direct contributions from sqrt-recording
    (required for sybil resistance via slashable operator attestations)."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "entry contribute()" in source
    assert "record_sqrt_share" in source


def test_qf_prevents_self_contribution():
    """A project cannot fund itself."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "sender != project_recipient" in source


def test_qf_role_separation_invariant():
    """The round operator and project recipient must be distinct."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "role_separation" in source
    assert "round_operator != project_recipient" in source


def test_qf_has_collusion_flagging():
    """Operator can flag known sybil/collusion contributions."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "flag_collusion" in source
    assert "flagged_contributions_mukrn" in source


def test_qf_has_round_timing():
    """QF round has explicit start/end levels."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "round_starts_at_level" in source
    assert "round_ends_at_level" in source
    assert "round_closed" in source


def test_qf_payout_bounded_invariant():
    """Payouts cannot exceed contributions + matching received."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "payout_bounded" in source


def test_qf_matching_pool_is_explicit_role():
    """The matching pool is a distinct address, separate from operator."""
    source = (EXAMPLES_DIR / "quadratic-funding.skald").read_text()
    assert "matching_pool_address" in source


# ---------------------------------------------------------------------------
# Retroactive PGF
# ---------------------------------------------------------------------------

def test_rpgf_has_badge_holder_voting():
    """RPGF uses badge-holders, not stake-weighted votes."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "record_vote" in source
    assert "max_score" in source
    assert "vote_count" in source


def test_rpgf_score_bounded_invariant():
    """Score sum cannot exceed (max_score × vote_count)."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "score_sum_bounded" in source
    assert "score_sum <= max_score * vote_count" in source


def test_rpgf_eligibility_window():
    """Work must have shipped in the declared window."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "eligible_after_level" in source
    assert "eligible_before_level" in source
    assert "shipped_at_level" in source


def test_rpgf_eligibility_window_invariant():
    """The shipping date invariant ensures retroactivity."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "ship_date_in_window" in source
    assert "shipped_at_level >= eligible_after_level" in source


def test_rpgf_has_disqualification():
    """Round operator can disqualify a fraudulent nomination."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "entry disqualify" in source
    assert "disqualification_reason" in source


def test_rpgf_disqualified_no_payout():
    """A disqualified nomination cannot withdraw funds."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    # The withdraw_to_recipient must have the !disqualified guard.
    assert "require !disqualified" in source


def test_rpgf_has_evidence_tracking():
    """Evidence count increments via the attestation registry pattern."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "record_evidence" in source
    assert "evidence_count" in source


def test_rpgf_role_separation():
    """Recipient cannot be the round operator."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "recipient != round_operator" in source


def test_rpgf_median_score_recorded():
    """The off-chain coordinator records median + share via dedicated entry."""
    source = (EXAMPLES_DIR / "retroactive-pgf.skald").read_text()
    assert "record_median_and_share" in source
    assert "median_score" in source


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------

def test_both_templates_use_attestation_pattern():
    """Both templates describe the operator-attestation pattern in comments."""
    for filename in PGF_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "attestation" in source.lower(), f"{filename} should reference attestation pattern"
        assert "slashable" in source.lower(), f"{filename} should mention slashing as anti-collusion"


def test_both_templates_have_matching_pool_role():
    """Both templates separate contribution/voting from payout via a matching pool."""
    for filename in PGF_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "matching_pool_address" in source, f"{filename} missing matching_pool_address"


def test_both_have_round_close_gate():
    """Both templates require round closure before payout."""
    for filename in PGF_TEMPLATES:
        source = (EXAMPLES_DIR / filename).read_text()
        assert "round_closed" in source


if __name__ == "__main__":
    # Manual run for ad-hoc invocation.
    import inspect
    me = sys.modules[__name__]
    for name, obj in inspect.getmembers(me):
        if name.startswith("test_") and callable(obj):
            try:
                if "parametrize" in str(getattr(obj, "pytestmark", [])):
                    for fn in PGF_TEMPLATES:
                        obj(fn)
                else:
                    obj()
                print(f"  ✓ {name}")
            except Exception as e:
                print(f"  ✗ {name}: {e}")
