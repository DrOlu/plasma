"""Sigma -> WHIDS gene conversion: structure, modifiers, skips."""
import json
from pathlib import Path

import pytest

from plasma import sigma


def _rule(**kw):
    base = {
        "title": "Test rule",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.t1059.001"],
    }
    base.update(kw)
    return base


def test_converts_process_creation_and_tags():
    gene = sigma.convert_rule(_rule())
    assert gene["Meta"]["EventIDs"] == [1]
    assert gene["Meta"]["Channels"] == [sigma.CHANNEL_SYSMON]
    assert gene["Meta"]["Criticality"] == 8
    assert "T1059.001" in gene["Tags"] and "Sigma" in gene["Tags"]
    assert gene["Matches"] == [
        "$selection_image: Image ~= '(?i:\\\\powershell\\.exe$)'"]
    assert gene["Condition"] == "($selection_image)"


def test_list_values_become_alternation():
    gene = sigma.convert_rule(_rule(detection={
        "selection": {"CommandLine|contains": ["-enc", "-encodedcommand"]},
        "condition": "selection",
    }))
    assert "(?:" in gene["Matches"][0]
    assert "-enc" in gene["Matches"][0]
    assert "-encodedcommand" in gene["Matches"][0]


def test_condition_and_not_filter():
    gene = sigma.convert_rule({
        "title": "rundll32",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection": {
            "selection": {"EventID": 1, "Image|endswith": "\\rundll32.exe"},
            "filter": {"CommandLine|contains": "shell32.dll"},
            "condition": "selection and not filter",
        },
        "level": "medium",
    })
    assert gene["Meta"]["EventIDs"] == [1]
    assert "not" not in gene["Condition"]
    assert "!" in gene["Condition"]          # gene grammar, not Sigma syntax
    assert gene["Condition"].count("$selection_") >= 1


def test_pipe_created_maps_to_both_event_ids():
    gene = sigma.convert_rule(_rule(detection={
        "selection": {"PipeName|startswith": "\\psexec"},
        "condition": "selection",
    }, logsource={"product": "windows", "category": "pipe_created"}))
    assert gene["Meta"]["EventIDs"] == [17, 18]


def test_unsupported_logsource_is_refused():
    with pytest.raises(sigma.SigmaError, match="logsource"):
        sigma.convert_rule(_rule(logsource={"product": "linux",
                                            "category": "process_creation"}))


def test_quantified_condition_is_refused():
    with pytest.raises(sigma.SigmaError, match="not supported"):
        sigma.convert_rule(_rule(detection={
            "selection_a": {"Image|endswith": "a.exe"},
            "selection_b": {"Image|endswith": "b.exe"},
            "condition": "1 of selection*",
        }))


def test_convert_path_reports_skips(tmp_path):
    good = tmp_path / "good.yml"
    good.write_text(
        "title: Good\nlogsource:\n  product: windows\n  category: process_creation\n"
        "detection:\n  selection:\n    Image|endswith: '\\\\cmd.exe'\n"
        "  condition: selection\nlevel: low\n", encoding="utf-8")
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "title: Bad\nlogsource:\n  product: linux\n"
        "detection:\n  selection:\n    Image|endswith: 'x'\n"
        "  condition: selection\n", encoding="utf-8")
    result = sigma.convert_path(tmp_path)
    assert result["converted"] == 1
    assert result["files"] == 2
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["rule"] == "Bad"


def test_write_gen_refuses_duplicate_names(tmp_path):
    rule = sigma.convert_rule(_rule())
    out = tmp_path / "rules.gen"
    result = sigma.write_gen(out, [rule, dict(rule)])
    assert result["written"] == 1
    assert len(out.read_text().strip().splitlines()) == 1
    assert json.loads(out.read_text().splitlines()[0])["Name"].startswith("Sigma:")


def test_yaml_is_a_feature_dependency_not_a_startup_one(monkeypatch):
    """The CLI imports sigma unconditionally; yaml must load only on use."""
    import sys
    monkeypatch.setitem(sys.modules, "yaml", None)  # makes `import yaml` fail
    with pytest.raises(sigma.SigmaError, match="PyYAML"):
        sigma._yaml()


def test_cli_runs_with_pyyaml_blocked(tmp_path):
    """plasma coverage must work on a host with no PyYAML installed."""
    import subprocess
    import sys
    repo = Path(__file__).resolve().parent.parent
    code = """
import importlib.abc, sys
class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "yaml" or fullname.startswith("yaml."):
            raise ModuleNotFoundError("No module named 'yaml'")
        return None
sys.meta_path.insert(0, Blocker())
import plasma.cli as cli
raise SystemExit(cli.main(["coverage"]))
"""
    proc = subprocess.run([sys.executable, "-c", code], cwd=repo,
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "coverage_pct" in proc.stdout


def test_all_modifier_and_attribution():
    gene = sigma.convert_rule(_rule(
        author="Analyst X",
        detection={
            "selection": {"CommandLine|contains|all": ["-nop", "-w hidden"]},
            "condition": "selection",
        }))
    assert len(gene["Matches"]) == 2
    assert " and " in gene["Condition"]
    assert gene["Meta"]["Author"] == "Analyst X"
    assert "SigmaHQ" in gene["Tags"]


def test_unsupported_modifier_is_refused_not_silently_wrong():
    with pytest.raises(sigma.SigmaError, match="modifier"):
        sigma.convert_rule(_rule(detection={
            "selection": {"CommandLine|windash": "-enc"},
            "condition": "selection",
        }))


def test_convert_path_records_the_source_file(tmp_path):
    (tmp_path / "one.yml").write_text(
        "title: Sourced\nlogsource:\n  product: windows\n"
        "  category: process_creation\ndetection:\n  selection:\n"
        "    Image|endswith: '\\\\cmd.exe'\n  condition: selection\nlevel: low\n")
    result = sigma.convert_path(tmp_path)
    assert "source: one.yml" in result["rules"][0]["Meta"]["Comment"]
