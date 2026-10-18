import json

EXPECTED = {
    "plasma_overview", "plasma_recent", "plasma_alerts", "plasma_processes",
    "plasma_network", "plasma_dns", "plasma_persistence", "plasma_search",
    "plasma_graph_overview", "plasma_graph_neighbors",
}


def load(instance_dir):
    return json.loads((instance_dir / "needle_menu.json").read_text(encoding="utf-8"))


def test_probe_count_and_names(instance_dir):
    menu = load(instance_dir)
    assert len(menu) <= 12
    assert {p["name"] for p in menu} == EXPECTED


def test_every_probe_has_triggers_and_schema(instance_dir):
    for probe in load(instance_dir):
        assert probe.get("description"), probe["name"]
        triggers = probe.get("triggers") or []
        assert len(triggers) >= 3, probe["name"]
        assert len(set(triggers)) == len(triggers), probe["name"]
        assert probe["parameters"]["type"] == "object"
        assert "properties" in probe["parameters"]


def test_arguments_are_caged(instance_dir):
    by_name = {p["name"]: p for p in load(instance_dir)}
    severity = by_name["plasma_alerts"]["parameters"]["properties"]["severity"]
    assert severity["enum"] == ["info", "low", "medium", "high", "critical"]
    ip = by_name["plasma_network"]["parameters"]["properties"]["dest_ip"]
    assert ip["pattern"].startswith("^")
    port = by_name["plasma_network"]["parameters"]["properties"]["dest_port"]
    assert port["minimum"] == 0 and port["maximum"] == 65535
    assert by_name["plasma_search"]["parameters"]["required"] == ["text"]
    assert by_name["plasma_graph_neighbors"]["parameters"]["required"] == ["node"]


def test_no_write_or_response_probes(instance_dir):
    names = " ".join(p["name"] for p in load(instance_dir))
    for forbidden in ("kill", "block", "isolate", "delete", "disable", "quarantine", "actuate"):
        assert forbidden not in names
