# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern.observability
==================

Structured logging and Prometheus-style metrics for Kern nodes.

Two layers:

1. **Structured logger** — JSON-line logs with consistent fields
   (timestamp, level, event, fields). Easy to parse with jq, ship to
   ELK / Loki, or pipe into Grafana.

2. **Metrics registry** — counters, gauges, and histograms with a
   text-format exporter compatible with Prometheus scrape. No external
   dependencies; the exporter is a small text formatter.

Both are zero-config: import and use. The RPC server exposes
`/metrics` for Prometheus scraping when the observability module is
loaded (see kern.rpc).
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Format log records as one JSON object per line.

    Standard fields: timestamp, level, name, event, message.
    Extra context fields are pulled from record.__dict__.
    """

    BASE_KEYS = {"name", "msg", "args", "levelname", "levelno", "pathname",
                 "filename", "module", "exc_info", "exc_text", "stack_info",
                 "lineno", "funcName", "created", "msecs", "relativeCreated",
                 "thread", "threadName", "processName", "process", "message",
                 "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        out: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Pull in any extra fields the caller passed via logger.info(..., extra=...)
        for k, v in record.__dict__.items():
            if k not in self.BASE_KEYS and not k.startswith("_"):
                # Only serialize JSON-safe values
                try:
                    json.dumps(v)
                    out[k] = v
                except (TypeError, ValueError):
                    out[k] = repr(v)
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, separators=(",", ":"))


def configure_structured_logging(level: int = logging.INFO,
                                  stream=sys.stdout) -> None:
    """Reconfigure the root logger to emit JSON-line logs."""
    root = logging.getLogger()
    # Remove any existing handlers (re-configurable for tests).
    for h in list(root.handlers):
        root.removeHandler(h)
    h = logging.StreamHandler(stream)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(level)


# ---------------------------------------------------------------------------
# Metrics registry
# ---------------------------------------------------------------------------

class Metric:
    """Base for typed metrics."""
    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._lock = Lock()


class Counter(Metric):
    """A monotonically-increasing counter (e.g., 'blocks_produced_total')."""
    def __init__(self, name: str, help_text: str = ""):
        super().__init__(name, help_text)
        self._values: Dict[Tuple[Tuple[str, str], ...], int] = defaultdict(int)

    def inc(self, n: int = 1, **labels) -> None:
        with self._lock:
            key = tuple(sorted(labels.items()))
            self._values[key] += n

    def value(self, **labels) -> int:
        key = tuple(sorted(labels.items()))
        return self._values[key]

    def render(self) -> List[str]:
        lines: List[str] = []
        if self.help_text:
            lines.append(f"# HELP {self.name} {self.help_text}")
        lines.append(f"# TYPE {self.name} counter")
        if not self._values:
            lines.append(f"{self.name} 0")
        else:
            for label_tuple, v in self._values.items():
                if label_tuple:
                    label_str = "{" + ",".join(
                        f'{k}="{val}"' for k, val in label_tuple
                    ) + "}"
                else:
                    label_str = ""
                lines.append(f"{self.name}{label_str} {v}")
        return lines


class Gauge(Metric):
    """A point-in-time value (e.g., 'mempool_size', 'peer_count')."""
    def __init__(self, name: str, help_text: str = ""):
        super().__init__(name, help_text)
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = defaultdict(float)

    def set(self, value: float, **labels) -> None:
        with self._lock:
            key = tuple(sorted(labels.items()))
            self._values[key] = value

    def inc(self, n: float = 1.0, **labels) -> None:
        with self._lock:
            key = tuple(sorted(labels.items()))
            self._values[key] += n

    def dec(self, n: float = 1.0, **labels) -> None:
        self.inc(-n, **labels)

    def value(self, **labels) -> float:
        key = tuple(sorted(labels.items()))
        return self._values[key]

    def render(self) -> List[str]:
        lines: List[str] = []
        if self.help_text:
            lines.append(f"# HELP {self.name} {self.help_text}")
        lines.append(f"# TYPE {self.name} gauge")
        if not self._values:
            lines.append(f"{self.name} 0")
        else:
            for label_tuple, v in self._values.items():
                if label_tuple:
                    label_str = "{" + ",".join(
                        f'{k}="{val}"' for k, val in label_tuple
                    ) + "}"
                else:
                    label_str = ""
                lines.append(f"{self.name}{label_str} {v}")
        return lines


class Histogram(Metric):
    """A distribution (e.g., 'block_time_seconds').

    Buckets are configurable; defaults span ~1ms to ~10s on a log scale —
    suitable for block times, tx-processing latencies, RPC durations.
    """
    DEFAULT_BUCKETS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0)

    def __init__(self, name: str, help_text: str = "",
                 buckets: Tuple[float, ...] = DEFAULT_BUCKETS):
        super().__init__(name, help_text)
        self.buckets = buckets
        self.counts: List[int] = [0] * len(buckets)
        self.sum: float = 0.0
        self.count: int = 0

    def observe(self, value: float) -> None:
        with self._lock:
            self.count += 1
            self.sum += value
            for i, b in enumerate(self.buckets):
                if value <= b:
                    self.counts[i] += 1

    def render(self) -> List[str]:
        lines: List[str] = []
        if self.help_text:
            lines.append(f"# HELP {self.name} {self.help_text}")
        lines.append(f"# TYPE {self.name} histogram")
        cumulative = 0
        for b, c in zip(self.buckets, self.counts):
            cumulative += c
            lines.append(f'{self.name}_bucket{{le="{b}"}} {cumulative}')
        lines.append(f'{self.name}_bucket{{le="+Inf"}} {self.count}')
        lines.append(f"{self.name}_sum {self.sum}")
        lines.append(f"{self.name}_count {self.count}")
        return lines


class Registry:
    """The global metrics registry. Singleton-style."""
    def __init__(self):
        self._metrics: Dict[str, Metric] = {}
        self._lock = Lock()

    def register(self, metric: Metric) -> Metric:
        with self._lock:
            if metric.name in self._metrics:
                return self._metrics[metric.name]  # idempotent
            self._metrics[metric.name] = metric
        return metric

    def counter(self, name: str, help_text: str = "") -> Counter:
        return self.register(Counter(name, help_text))  # type: ignore

    def gauge(self, name: str, help_text: str = "") -> Gauge:
        return self.register(Gauge(name, help_text))  # type: ignore

    def histogram(self, name: str, help_text: str = "",
                  buckets: Tuple[float, ...] = Histogram.DEFAULT_BUCKETS
                  ) -> Histogram:
        return self.register(Histogram(name, help_text, buckets))  # type: ignore

    def render(self) -> str:
        """Render all metrics in Prometheus text-exposition format."""
        lines: List[str] = []
        with self._lock:
            for m in self._metrics.values():
                lines.extend(m.render())
                lines.append("")  # blank line between metric families
        return "\n".join(lines).rstrip() + "\n"

    def clear(self) -> None:
        """Wipe the registry. For tests."""
        with self._lock:
            self._metrics.clear()


# Module-level singleton registry.
REGISTRY = Registry()


# Pre-declared metrics used across the codebase.
def _bootstrap_metrics() -> None:
    """Declare the canonical metrics so the registry is populated even
    before any operation increments anything."""
    REGISTRY.counter("kern_blocks_produced_total", "Number of blocks the local baker produced")
    REGISTRY.counter("kern_blocks_applied_total", "Number of blocks applied to local chain (own + peers)")
    REGISTRY.counter("kern_transactions_applied_total", "Transactions applied")
    REGISTRY.counter("kern_transactions_rejected_total", "Transactions that failed apply")
    REGISTRY.counter("kern_governance_proposals_total", "Governance proposals seen")
    REGISTRY.counter("kern_governance_activations_total", "Governance proposals that reached ACTIVATED")
    REGISTRY.counter("kern_governance_equivocations_total", "Equivocations detected")
    REGISTRY.counter("kern_treasury_executions_total", "Treasury proposals executed")

    REGISTRY.gauge("kern_chain_height", "Current chain head level")
    REGISTRY.gauge("kern_mempool_size", "Number of transactions in mempool")
    REGISTRY.gauge("kern_peers_connected", "Number of connected P2P peers")
    REGISTRY.gauge("kern_total_supply_mukrn", "Total KRN supply in mukrn")
    REGISTRY.gauge("kern_validator_count", "Number of registered validators")

    REGISTRY.histogram("kern_block_apply_seconds", "Time to apply a block to state")
    REGISTRY.histogram("kern_tx_apply_seconds", "Time to apply a single transaction")
    REGISTRY.histogram("kern_rpc_request_seconds", "RPC handler latency",
                       buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0))


_bootstrap_metrics()


# ---------------------------------------------------------------------------
# Public convenience accessors
# ---------------------------------------------------------------------------

def counter(name: str, help_text: str = "") -> Counter:
    return REGISTRY.counter(name, help_text)


def gauge(name: str, help_text: str = "") -> Gauge:
    return REGISTRY.gauge(name, help_text)


def histogram(name: str, help_text: str = "") -> Histogram:
    return REGISTRY.histogram(name, help_text)


def render_metrics() -> str:
    """The exposition payload for Prometheus scrape."""
    return REGISTRY.render()


# Timer context manager for histograms.
class Timer:
    """`with observe_latency("kern_rpc_request_seconds"):  ...`"""
    def __init__(self, hist_name: str):
        self.hist_name = hist_name
        self.start = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        elapsed = time.perf_counter() - self.start
        h = REGISTRY._metrics.get(self.hist_name)
        if isinstance(h, Histogram):
            h.observe(elapsed)


def observe_latency(hist_name: str) -> Timer:
    return Timer(hist_name)
