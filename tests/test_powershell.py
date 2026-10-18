import json
import shutil
import subprocess

import pytest

from conftest import INSTANCE, SAMPLES

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")


def ps(tool=None, args=None, events=None, coverage=False):
    cmd = ["pwsh", "-NoProfile", "-File", str(INSTANCE / "bridge.ps1")]
    if coverage:
        cmd.append("-Coverage")
    else:
        cmd += ["-Tool", tool, "-ArgsJson", json.dumps(args or {})]
    if events:
        cmd += ["-EventsPath", str(events)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_coverage():
    data = ps(coverage=True)
    assert data["total"] == 107
    assert data["coverage_pct"] == 100.0


def test_overview_parity():
    data = ps("plasma_overview", events=SAMPLES)
    assert data["events"] == 107
    assert data["alerts"] == 6
    assert data["killed"] == 2


def test_alert_filter_parity():
    data = ps("plasma_alerts", {"severity": "critical"}, events=SAMPLES)
    assert data["count"] == 4


def test_search_parity():
    data = ps("plasma_search", {"text": "certutil"}, events=SAMPLES)
    assert data["count"] == 2


def test_unknown_probe_is_data():
    data = ps("kernel_kit", events=SAMPLES)
    assert "unknown probe" in data["error"]


def test_missing_store_is_data(tmp_path):
    data = ps("plasma_overview", events=tmp_path / "missing.jsonl")
    assert "event store not found" in data["error"]
