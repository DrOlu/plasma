import json

import pytest


def test_coverage_is_total(bridge):
    cov = bridge.coverage()
    assert cov["total"] == 107
    assert cov["parsed"] == 107
    assert cov["failed"] == 0
    assert cov["coverage_pct"] == 100.0


def test_overview(bridge):
    out = bridge.plasma_overview()
    assert out["events"] == 107
    assert out["alerts"] == 6
    assert out["killed"] == 2
    assert out["by_host"]["WS1"] == 52
    assert out["coverage_pct"] == 100.0


def test_alerts_filter(bridge):
    out = bridge.plasma_alerts(severity="critical")
    assert out["count"] == 4
    assert all(a["severity"] == "critical" for a in out["alerts"])
    high = bridge.plasma_alerts(severity="high")
    assert high["count"] == 2


def test_processes(bridge):
    out = bridge.plasma_processes(process="powershell")
    assert out["count"] >= 1
    assert any("powershell" in (e.get("process") or "").lower() for e in out["events"])


def test_network(bridge):
    out = bridge.plasma_network(dest_port=4444)
    assert out["count"] >= 1
    assert all(c["dest_port"] == 4444 for c in out["connections"])


def test_dns(bridge):
    out = bridge.plasma_dns()
    assert out["count"] >= 10
    assert out["by_query"]


def test_persistence(bridge):
    out = bridge.plasma_persistence()
    assert out["count"] >= 2
    assert out["by_artifact"]


def test_search(bridge):
    out = bridge.plasma_search(text="certutil")
    assert out["count"] >= 2
    empty = bridge.plasma_search(text="")
    assert "error" in empty


def test_recent_limit(bridge):
    out = bridge.plasma_recent(limit=5)
    assert out["returned"] == 5
    assert len(out["events"]) == 5


def test_graph_overview(bridge):
    out = bridge.plasma_graph_overview()
    assert out["events"] == 107
    assert "process" in out["nodes"]
    assert out["edges"]["connects_to"] > 0


def test_graph_neighbors(bridge):
    out = bridge.plasma_graph_neighbors(node="185.220.101.4")
    assert out["found"] is True
    assert out["events"] >= 1
    assert "process" in out["neighbors"]
    missing = bridge.plasma_graph_neighbors(node="no-such-entity-xyz")
    assert missing["found"] is False


def test_unknown_probe(bridge):
    assert "error" in bridge.run_tool("delete_everything")


def test_bad_arguments(bridge):
    assert "error" in bridge.run_tool("plasma_recent", {"bogus": 1})


def test_event_store_missing_is_data(bridge, monkeypatch):
    monkeypatch.setenv("PLASMA_EVENTS", "/nonexistent/plasma-events.jsonl")
    out = bridge.plasma_overview()
    assert "error" in out
