"""The shipped Sysmon baseline config must log the events the rules need."""
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from plasma.cli import SYSMON_BASELINE_CONFIG


def _root():
    return ET.fromstring(SYSMON_BASELINE_CONFIG)


def test_config_is_wellformed_sysmon_xml():
    root = _root()
    assert root.tag == "Sysmon"
    assert root.get("schemaversion") == "4.90"
    assert root.find("EventFiltering") is not None


def test_required_event_types_are_present():
    filtering = _root().find("EventFiltering")
    names = {child.tag for child in filtering}
    for required in ("ProcessCreate", "NetworkConnect", "DnsQuery",
                     "RegistryEvent", "FileDelete"):
        assert required in names, required


def test_registry_events_are_logged():
    """onmatch=exclude with no rules means 'exclude nothing' -> log all.

    The run-key and service rules depend on EventIDs 12/13 arriving; an
    empty exclude filter is how this config keeps registry telemetry on.
    """
    reg = _root().find("EventFiltering/RegistryEvent")
    assert reg is not None
    assert reg.get("onmatch") == "exclude"
    assert len(list(reg)) == 0


def test_file_delete_is_include_with_executable_extensions():
    fd = _root().find("EventFiltering/FileDelete")
    assert fd is not None and fd.get("onmatch") == "include"
    extensions = {el.text for el in fd}
    assert ".exe" in extensions and ".ps1" in extensions and ".zip" in extensions
    # bounded: we do not log every file deletion
    assert len(extensions) <= 20
    for el in fd:
        assert el.get("condition") == "end with"


# ---------------------------------------------------------------------------
# config convergence on upgrade
# ---------------------------------------------------------------------------

def test_write_sysmon_config_is_byte_identical(tmp_path):
    from plasma import cli
    path = cli.write_sysmon_config(tmp_path / "tools")
    assert path.read_text(encoding="utf-8") == cli.SYSMON_BASELINE_CONFIG
    # idempotent: a second write leaves one file with the same content
    again = cli.write_sysmon_config(tmp_path / "tools")
    assert again.read_text(encoding="utf-8") == cli.SYSMON_BASELINE_CONFIG


def test_apply_sysmon_config_invokes_config_reload(tmp_path, monkeypatch):
    """An old node keeps its install-time config unless we re-apply ours."""
    from plasma import cli
    system_root = tmp_path / "Windows"
    system_root.mkdir()
    (system_root / "Sysmon64.exe").write_bytes(b"MZ")
    monkeypatch.setenv("SystemRoot", str(system_root))
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="Configuration updated.", stderr="")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    result = cli._apply_sysmon_config(tmp_path / "tools")

    assert result["ok"] is True
    assert seen["cmd"][0].endswith("Sysmon64.exe")
    assert seen["cmd"][1] == "-c"
    cfg = seen["cmd"][2]
    assert cfg.endswith("plasma-sysmon-baseline.xml")
    assert "<FileDelete" in Path(cfg).read_text(encoding="utf-8")


def test_apply_sysmon_config_missing_binary(tmp_path, monkeypatch):
    from plasma import cli
    monkeypatch.setenv("SystemRoot", str(tmp_path / "empty"))
    result = cli._apply_sysmon_config(tmp_path / "tools")
    assert result["ok"] is False and "not found" in result["reason"]


def test_pipe_events_include_create_and_connect():
    """The named-pipe rule cites 17 and 18; enabling only CreatePipe made
    half the rule dormant (field-found by triggering a pipe connect)."""
    pipe = _root().find("EventFiltering/PipeEvent")
    assert pipe is not None and pipe.get("onmatch") == "include"
    types = {el.text for el in pipe if el.tag == "EventType"}
    assert types == {"CreatePipe", "ConnectPipe"}


def test_dns_is_excluded_by_default_and_narrow_include_is_opt_in():
    from plasma import cli
    default = ET.fromstring(cli.sysmon_baseline_config())
    dns = default.find("EventFiltering/DnsQuery")
    assert dns is not None and dns.get("onmatch") == "exclude"
    assert len(list(dns)) == 0

    narrow = ET.fromstring(cli.sysmon_baseline_config(
        ["assets.internal", "assets.internal"]))
    dns = narrow.find("EventFiltering/DnsQuery")
    assert dns is not None and dns.get("onmatch") == "include"
    names = [el.text for el in dns if el.tag == "QueryName"]
    assert names == [".assets.internal"]


def test_sysmon_config_escapes_dns_suffix():
    from plasma import cli
    text = cli.sysmon_baseline_config(['a&b.example'])
    assert "a&amp;b.example" in text
    # still well-formed after escaping
    ET.fromstring(text)
