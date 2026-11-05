"""persistence_deep: normalization, suspect heuristic, PS template shape."""
import json

import pytest

from plasma import deep


def test_ps_template_formats_and_covers_all_sources():
    script = deep._PS_TEMPLATE.format(cap=40)
    for marker in ("run_key", "service", "scheduled_task", "ifeo",
                   "winlogon", "wmi_filter", "wmi_consumer", "wmi_bindings",
                   "Get-AuthenticodeSignature"):
        assert marker in script, marker
    # no stray unformatted slots
    assert "{" + "cap" not in script.replace("{cap}", "")


def test_normalize_flags_unsigned_outside_windows():
    payload = {
        "rows": [
            {"source": "run_key", "name": "Updater", "detail": "HKLM:...Run",
             "path": r"C:\Users\bob\AppData\evil.exe"},
            {"source": "service", "name": "Sysmon64", "detail": "start=Auto as=LocalSystem",
             "path": r"C:\Windows\Sysmon64.exe"},
            {"source": "scheduled_task", "name": "Backup", "detail": "path=\\ state=Ready",
             "path": "C:\\Program Files\\Backup\\taskbak.exe"},
        ],
        "signatures": {
            r"c:\users\bob\appdata\evil.exe": {"signed": False, "signer": ""},
            r"c:\windows\sysmon64.exe": {"signed": True,
                                         "signer": "CN=Microsoft Windows"},
            r"c:\program files\backup\taskbak.exe": {"signed": True,
                                                     "signer": "CN=Backup Co"},
        },
    }
    result = deep.normalize(payload)
    assert result["total"] == 3
    assert result["by_source"] == {"run_key": 1, "service": 1, "scheduled_task": 1}
    assert result["suspect_count"] == 1
    assert result["suspects"][0]["name"] == "Updater"
    # signed + in-Windows items are not suspects
    items = {i["name"]: i for i in result["items"]}
    assert items["Sysmon64"]["suspect"] is False
    assert items["Backup"]["suspect"] is False


def test_normalize_handles_missing_signatures_and_junk():
    result = deep.normalize({"rows": [{"source": "wmi_bindings", "name": "0",
                                       "detail": "bindings", "path": ""}],
                             "signatures": {}})
    assert result["total"] == 1
    item = result["items"][0]
    assert item["signed"] is None
    assert item["suspect"] is False      # not an executable path at all


def test_normalize_empty_payload():
    result = deep.normalize({"rows": [], "signatures": {}})
    assert result == {"items": [], "by_source": {}, "suspect_count": 0,
                      "suspects": [], "total": 0}


def test_run_reports_probe_errors_as_data(monkeypatch):
    monkeypatch.setattr(deep, "_run_ps", lambda cap=40: {"error": "no powershell"})
    result = deep.run()
    assert result == {"error": "no powershell"}


def test_run_writes_json_out(tmp_path, monkeypatch):
    payload = {"rows": [{"source": "run_key", "name": "X", "detail": "d",
                         "path": r"C:\Windows\ok.exe"}],
               "signatures": {r"c:\windows\ok.exe": {"signed": True,
                                                     "signer": "CN=Microsoft"}}}
    monkeypatch.setattr(deep, "_run_ps", lambda cap=40: payload)
    out = tmp_path / "deep" / "persistence.json"
    result = deep.run(out=out)
    assert result["written"] == str(out)
    saved = json.loads(out.read_text())
    assert saved["probe"] == "persistence_deep"
    assert saved["total"] == 1
