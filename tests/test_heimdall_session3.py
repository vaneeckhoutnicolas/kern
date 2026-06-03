# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""Tests for Heimdall Session 3 — monitoring stack.

Covers:
- All 6 Grafana dashboard JSON files: parse, structure, datasource template var,
  presence of required panel types, valid PromQL refs against our metrics.py
- The Prometheus alerting rules YAML: parse, validate groups and rule structure,
  each metric referenced exists in our metrics.py, runbook URLs point at the
  ops-runbook anchors that actually exist.
- The Docker-compose monitoring stack YAML: parse, validate services declared,
  volumes consistent.
- The Prometheus + Grafana provisioning YAMLs: parse and check minimal sanity.

These tests don't spin up containers — they only validate the configs are
internally consistent and reference metrics that exist on our side.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kern_explorer import metrics as kern_metrics


MONITORING_DIR = Path(__file__).resolve().parent.parent / "kern_explorer" / "monitoring"
GRAFANA_DIR = MONITORING_DIR / "grafana"
ALERTS_FILE = MONITORING_DIR / "alerts" / "kern-alerts.yml"
DOCKER_DIR = MONITORING_DIR / "docker"
RUNBOOK_FILE = Path(__file__).resolve().parent.parent / "docs" / "heimdall-ops-runbook.md"


# ===========================================================================
# Helpers
# ===========================================================================

def metric_names_emitted_by_heimdall() -> set[str]:
    """Extract the set of metric names emitted by kern_explorer.metrics.

    We read the source of metrics.py and pick up everything that starts with
    `kern_` or `heimdall_` in either a `_write(buf, "name", …)` call or a
    raw `buf.write(f'name{…}')` line.
    """
    src = Path(kern_metrics.__file__).read_text()
    names = set()
    # _write(buf, "metric_name", ...)
    for m in re.finditer(r'_write\(buf,\s*"([a-z_]+)"', src):
        names.add(m.group(1))
    # buf.write(f'metric_name{...}') for per-label series
    for m in re.finditer(r'buf\.write\(f?\'(kern_[a-z_]+)', src):
        names.add(m.group(1))
    for m in re.finditer(r'buf\.write\(f?\'(heimdall_[a-z_]+)', src):
        names.add(m.group(1))
    return names


def extract_metric_refs(text: str) -> set[str]:
    """Extract all `kern_*` and `heimdall_*` identifiers from a text blob
    (used to find metric references in dashboard JSON exprs and alert rules)."""
    return set(re.findall(r'\b(kern_[a-z_]+|heimdall_[a-z_]+)', text))


# ===========================================================================
# Grafana dashboards
# ===========================================================================

class TestGrafanaDashboards:

    EXPECTED_FILES = [
        "network-health.json",
        "attestations.json",
        "oracles.json",
        "sto-compliance.json",
        "public-goods.json",
        "governance.json",
        "heimdall-internals.json",
    ]

    def test_all_expected_dashboards_exist(self):
        present = {p.name for p in GRAFANA_DIR.glob("*.json")}
        for expected in self.EXPECTED_FILES:
            assert expected in present, f"missing dashboard: {expected}"

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_dashboard_is_valid_json(self, filename):
        p = GRAFANA_DIR / filename
        with open(p) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_dashboard_has_required_top_level_keys(self, filename):
        data = json.loads((GRAFANA_DIR / filename).read_text())
        assert "title" in data and isinstance(data["title"], str) and data["title"]
        assert "uid" in data and data["uid"], f"{filename} must have a uid"
        assert "panels" in data and isinstance(data["panels"], list)
        assert "schemaVersion" in data
        # Grafana 10+ uses schemaVersion >= 38
        assert data["schemaVersion"] >= 36, \
            f"{filename}: stale schemaVersion {data['schemaVersion']}"

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_dashboard_has_datasource_template_var(self, filename):
        data = json.loads((GRAFANA_DIR / filename).read_text())
        templating = data.get("templating", {}).get("list", [])
        assert any(t.get("name") == "DS_PROMETHEUS" and t.get("type") == "datasource"
                   for t in templating), \
            f"{filename}: must declare DS_PROMETHEUS template variable"

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_dashboard_panels_have_targets(self, filename):
        data = json.loads((GRAFANA_DIR / filename).read_text())
        for panel in data["panels"]:
            # `text`, `row`, `dashlist` etc. don't need targets — skip those
            if panel.get("type") in ("text", "row", "dashlist"):
                continue
            assert "targets" in panel, \
                f"{filename}: panel '{panel.get('title', panel.get('id'))}' missing targets"
            assert len(panel["targets"]) > 0

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_dashboard_uses_only_emitted_metrics(self, filename):
        emitted = metric_names_emitted_by_heimdall()
        data = json.loads((GRAFANA_DIR / filename).read_text())
        # Collect all PromQL expressions from all targets
        for panel in data["panels"]:
            for target in panel.get("targets", []):
                expr = target.get("expr", "")
                refs = extract_metric_refs(expr)
                for ref in refs:
                    assert ref in emitted, (
                        f"{filename} panel '{panel.get('title')}' uses metric "
                        f"{ref!r} which is NOT emitted by kern_explorer.metrics"
                    )


# ===========================================================================
# Prometheus alerting rules
# ===========================================================================

class TestAlertingRules:

    @pytest.fixture
    def rules(self):
        with open(ALERTS_FILE) as f:
            return yaml.safe_load(f)

    def test_alerts_file_parses(self, rules):
        assert isinstance(rules, dict)
        assert "groups" in rules
        assert isinstance(rules["groups"], list)
        assert len(rules["groups"]) >= 4   # l1, attestations, oracles, sto

    def test_each_group_has_required_fields(self, rules):
        for g in rules["groups"]:
            assert "name" in g and g["name"]
            assert "rules" in g and isinstance(g["rules"], list)
            assert len(g["rules"]) > 0

    def test_each_alert_has_required_fields(self, rules):
        for g in rules["groups"]:
            for r in g["rules"]:
                assert "alert" in r, f"rule in group {g['name']} missing 'alert' name"
                assert "expr" in r, f"alert {r.get('alert')} missing 'expr'"
                assert "labels" in r, f"alert {r['alert']} missing 'labels'"
                assert "severity" in r["labels"], \
                    f"alert {r['alert']} missing severity label"
                assert r["labels"]["severity"] in ("critical", "warning", "info")
                assert "annotations" in r, f"alert {r['alert']} missing annotations"
                assert "summary" in r["annotations"], \
                    f"alert {r['alert']} missing summary annotation"
                assert "description" in r["annotations"], \
                    f"alert {r['alert']} missing description annotation"

    def test_critical_alerts_have_runbook_url(self, rules):
        for g in rules["groups"]:
            for r in g["rules"]:
                if r["labels"]["severity"] == "critical":
                    assert "runbook_url" in r["annotations"], (
                        f"critical alert {r['alert']} must have runbook_url"
                    )

    def test_all_referenced_metrics_exist(self, rules):
        emitted = metric_names_emitted_by_heimdall()
        for g in rules["groups"]:
            for r in g["rules"]:
                refs = extract_metric_refs(r["expr"])
                for ref in refs:
                    assert ref in emitted, (
                        f"alert {r['alert']} references metric {ref!r} "
                        f"not emitted by kern_explorer.metrics"
                    )

    def test_runbook_anchors_exist(self, rules):
        """Every runbook_url that points to docs/heimdall-ops-runbook.md
        must reference an anchor that actually exists in that file.

        We accept both `#anchor-name` and full URLs containing `runbook#anchor`.
        """
        runbook_text = RUNBOOK_FILE.read_text()
        # Markdown auto-anchors are H2/H3 lowercase with hyphens; we also use
        # explicit `{#name}` syntax in places. Collect both.
        explicit_anchors = set(re.findall(r'\{#([a-z0-9-]+)\}', runbook_text))
        # Also accept H2/H3 headings (lowercased, spaces → hyphens)
        for line in runbook_text.splitlines():
            m = re.match(r'^#{1,4}\s+(.+?)(?:\s*\{#[^}]+\})?$', line)
            if m:
                title = m.group(1).strip().lower()
                slug = re.sub(r'[^a-z0-9-]+', '-', title).strip('-')
                explicit_anchors.add(slug)

        for g in rules["groups"]:
            for r in g["rules"]:
                url = r.get("annotations", {}).get("runbook_url", "")
                if "runbook#" in url:
                    anchor = url.split("#", 1)[1]
                    assert anchor in explicit_anchors, (
                        f"alert {r['alert']} runbook_url anchor {anchor!r} "
                        f"not found in docs/heimdall-ops-runbook.md"
                    )


# ===========================================================================
# Docker stack
# ===========================================================================

class TestDockerComposeStack:

    @pytest.fixture
    def compose(self):
        with open(DOCKER_DIR / "docker-compose.monitoring.yml") as f:
            return yaml.safe_load(f)

    def test_compose_parses(self, compose):
        assert isinstance(compose, dict)
        assert "services" in compose

    def test_all_required_services_present(self, compose):
        services = compose["services"]
        for required in ("heimdall", "prometheus", "alertmanager", "grafana"):
            assert required in services, f"service {required} missing from compose"

    def test_prometheus_mounts_alert_rules(self, compose):
        prom = compose["services"]["prometheus"]
        volumes = prom.get("volumes", [])
        # The kern-alerts.yml must be mounted to /etc/prometheus/rules/
        assert any("kern-alerts.yml" in v for v in volumes), \
            "Prometheus must mount kern-alerts.yml from ../alerts/"

    def test_grafana_mounts_dashboards(self, compose):
        graf = compose["services"]["grafana"]
        volumes = graf.get("volumes", [])
        assert any("dashboards" in v for v in volumes), \
            "Grafana must mount the dashboards directory"
        assert any("datasources" in v for v in volumes), \
            "Grafana must mount the datasources provisioning file"


class TestPrometheusConfig:

    def test_prometheus_yml_parses(self):
        with open(DOCKER_DIR / "prometheus.yml") as f:
            data = yaml.safe_load(f)
        assert "scrape_configs" in data
        # Must scrape Heimdall
        targets = []
        for job in data["scrape_configs"]:
            for sc in job.get("static_configs", []):
                targets.extend(sc.get("targets", []))
        assert any("heimdall" in t for t in targets), \
            "prometheus.yml must include a heimdall scrape target"

    def test_prometheus_references_alert_file(self):
        with open(DOCKER_DIR / "prometheus.yml") as f:
            data = yaml.safe_load(f)
        rule_files = data.get("rule_files", [])
        assert any("kern-alerts" in f for f in rule_files), \
            "prometheus.yml must reference kern-alerts.yml in rule_files"


class TestGrafanaProvisioning:

    def test_datasources_yml_parses(self):
        with open(DOCKER_DIR / "grafana-datasources.yml") as f:
            data = yaml.safe_load(f)
        assert "datasources" in data
        names = [d["name"] for d in data["datasources"]]
        assert "Prometheus" in names

    def test_dashboards_provider_parses(self):
        with open(DOCKER_DIR / "grafana-dashboards-provider.yml") as f:
            data = yaml.safe_load(f)
        assert "providers" in data
        assert len(data["providers"]) >= 1
