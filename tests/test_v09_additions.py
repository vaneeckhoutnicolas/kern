# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for v0.9: observability (logs/metrics), fuzzing harness,
chaos / stress tests."""

import io
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from kern.fuzzing import (
    fuzz_evm_determinism,
    fuzz_governance_invariants,
    fuzz_transaction_safety,
    random_bytecode,
    run_all_fuzzers,
)
from kern.observability import (
    Counter,
    Gauge,
    Histogram,
    JsonFormatter,
    REGISTRY,
    Registry,
    configure_structured_logging,
    observe_latency,
    render_metrics,
)


# ===========================================================================
# Observability — structured logging
# ===========================================================================

def test_json_formatter_emits_valid_json():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="hello %s", args=("world",), exc_info=None,
    )
    line = fmt.format(record)
    parsed = json.loads(line)
    assert parsed["msg"] == "hello world"
    assert parsed["level"] == "INFO"


def test_json_formatter_includes_extras():
    fmt = JsonFormatter()
    record = logging.LogRecord(
        name="test", level=logging.WARNING, pathname="", lineno=0,
        msg="event", args=(), exc_info=None,
    )
    record.event = "block_baked"
    record.level_int = 42
    line = fmt.format(record)
    parsed = json.loads(line)
    assert parsed["event"] == "block_baked"
    assert parsed["level_int"] == 42


def test_configure_structured_logging():
    stream = io.StringIO()
    configure_structured_logging(level=logging.DEBUG, stream=stream)
    logger = logging.getLogger("test.kern")
    logger.info("test event", extra={"event": "test"})
    output = stream.getvalue()
    assert output  # something was written
    parsed = json.loads(output.strip())
    assert parsed["msg"] == "test event"
    assert parsed["event"] == "test"


# ===========================================================================
# Observability — metrics
# ===========================================================================

def test_counter_increments():
    reg = Registry()
    c = reg.counter("test_counter")
    assert c.value() == 0
    c.inc()
    assert c.value() == 1
    c.inc(5)
    assert c.value() == 6


def test_counter_with_labels():
    reg = Registry()
    c = reg.counter("test_counter")
    c.inc(1, status="ok")
    c.inc(2, status="ok")
    c.inc(3, status="err")
    assert c.value(status="ok") == 3
    assert c.value(status="err") == 3


def test_gauge_set_and_modify():
    reg = Registry()
    g = reg.gauge("test_gauge")
    g.set(10)
    assert g.value() == 10
    g.inc(5)
    assert g.value() == 15
    g.dec(3)
    assert g.value() == 12


def test_histogram_observes():
    reg = Registry()
    h = reg.histogram("test_hist")
    for v in [0.001, 0.01, 0.1, 1.0]:
        h.observe(v)
    assert h.count == 4
    assert h.sum == pytest.approx(1.111)


def test_render_metrics_prometheus_format():
    reg = Registry()
    c = reg.counter("kern_blocks_total", help_text="Total blocks")
    c.inc(42)
    output = reg.render()
    assert "# HELP kern_blocks_total Total blocks" in output
    assert "# TYPE kern_blocks_total counter" in output
    assert "kern_blocks_total 42" in output


def test_render_metrics_includes_all_canonical():
    """The canonical metrics declared at module import are renderable."""
    output = render_metrics()
    # A handful of expected names:
    for name in [
        "kern_blocks_applied_total",
        "kern_transactions_applied_total",
        "kern_chain_height",
        "kern_total_supply_mukrn",
    ]:
        assert name in output


def test_observe_latency_records_to_histogram():
    h = REGISTRY._metrics["kern_block_apply_seconds"]
    initial_count = h.count
    with observe_latency("kern_block_apply_seconds"):
        time.sleep(0.001)
    assert h.count == initial_count + 1


# ===========================================================================
# Fuzzing — EVM determinism
# ===========================================================================

def test_random_bytecode_returns_bytes():
    import random as r
    rng = r.Random(42)
    code = random_bytecode(rng)
    assert isinstance(code, bytes)
    assert len(code) > 0


def test_fuzz_evm_determinism_passes_100_iterations():
    """Running 100 random programs, all should produce identical traces
    on repeated execution (commitment determinism)."""
    result = fuzz_evm_determinism(iterations=100, seed=1)
    assert result["success"], f"Failures: {result['failures']}"
    assert result["iterations"] == 100


def test_fuzz_evm_determinism_seeded_reproducible():
    """Same seed → same result."""
    r1 = fuzz_evm_determinism(iterations=50, seed=42)
    r2 = fuzz_evm_determinism(iterations=50, seed=42)
    assert r1["halted_count"] == r2["halted_count"]
    assert r1["reverted_count"] == r2["reverted_count"]


# ===========================================================================
# Fuzzing — transaction safety
# ===========================================================================

def test_fuzz_transaction_safety_conserves_supply():
    result = fuzz_transaction_safety(iterations=100, seed=1)
    assert result["supply_conserved"]
    assert result["success"], f"Failures: {result['failures']}"


def test_fuzz_transaction_safety_makes_some_successful():
    """Sanity: at least some random txs should succeed."""
    result = fuzz_transaction_safety(iterations=200, seed=1)
    assert result["successful"] > 0


# ===========================================================================
# Fuzzing — governance invariants
# ===========================================================================

def test_fuzz_governance_invariants_passes():
    result = fuzz_governance_invariants(iterations=100, seed=1)
    assert result["success"], f"Failures: {result['failures']}"


def test_fuzz_governance_invariants_creates_proposals():
    result = fuzz_governance_invariants(iterations=100, seed=42)
    assert result["proposals_created"] > 0


# ===========================================================================
# Composite chaos run
# ===========================================================================

def test_run_all_fuzzers_passes_at_low_iterations():
    """Combined fuzzing run with modest iteration count.
    The chaos test in CI / nightly bumps iterations to 10000."""
    result = run_all_fuzzers(iterations=50, seed=7)
    assert result["overall_success"], result


# ===========================================================================
# Chaos: long-running scenarios
# ===========================================================================

@pytest.mark.skip(reason="slow chaos test — run with --no-skip or in nightly CI")
def test_chaos_evm_determinism_1000_iter():
    """1000-iteration determinism check. Slower, marked slow."""
    result = fuzz_evm_determinism(iterations=1000, seed=0)
    assert result["success"], f"Failures: {result['failures'][:3]}"


@pytest.mark.skip(reason="slow chaos test — run with --no-skip or in nightly CI")
def test_chaos_governance_500_iter():
    result = fuzz_governance_invariants(iterations=500, seed=0)
    assert result["success"], result["failures"][:3]


if __name__ == "__main__":
    import inspect
    me = sys.modules[__name__]
    tests = [name for name, obj in inspect.getmembers(me)
             if name.startswith("test_") and callable(obj)]
    for t in tests:
        getattr(me, t)()
        print(f"  ✓ {t}")
    print(f"All {len(tests)} v0.9 tests passed.")
