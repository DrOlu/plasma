"""Engine selection tests. Skipped unless PLASMA_ENGINE and PLASMA_MODEL are set."""
import json
import subprocess

import pytest

from conftest import ROOT, engine_paths

GOLDEN = [
    ("show me the alerts", "plasma_alerts"),
    ("critical alerts", "plasma_alerts"),
    ("security overview", "plasma_overview"),
    ("what happened on this endpoint", "plasma_overview"),
    ("recent events", "plasma_recent"),
    ("latest events on WS1", "plasma_recent"),
    ("which processes ran", "plasma_processes"),
    ("suspicious processes", "plasma_processes"),
    ("outbound connections", "plasma_network"),
    ("network traffic", "plasma_network"),
    ("dns lookups", "plasma_dns"),
    ("which domains were resolved", "plasma_dns"),
    ("any persistence", "plasma_persistence"),
    ("run key persistence", "plasma_persistence"),
    ("find encoded powershell", "plasma_search"),
    ("search for certutil", "plasma_search"),
    ("graph overview", "plasma_graph_overview"),
    ("neighbors of p.exe", "plasma_graph_neighbors"),
    ("what connects to 185.220.101.4", "plasma_graph_neighbors"),
]


@pytest.fixture(scope="module")
def engine():
    eng, model = engine_paths()
    if not eng:
        pytest.skip("PLASMA_ENGINE/PLASMA_MODEL not set")
    return eng, model


def pick(engine, prompt):
    eng, model = engine
    proc = subprocess.run(
        [str(eng), "--model", str(model),
         "--tools", str(ROOT / "instance" / "needle_menu.json"),
         "--prompt", prompt],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    calls = data.get("function_calls") or []
    return calls[0]["name"] if calls else None


@pytest.mark.parametrize("prompt,expected", GOLDEN)
def test_selection_matrix(engine, prompt, expected):
    assert pick(engine, prompt) == expected


def test_engine_is_deterministic(engine):
    first = pick(engine, "show me the alerts")
    second = pick(engine, "show me the alerts")
    assert first == second == "plasma_alerts"
