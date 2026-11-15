"""Sigma -> WHIDS gene conversion: structure, modifiers, skips."""
import json

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
    assert "and not" in gene["Condition"]
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
