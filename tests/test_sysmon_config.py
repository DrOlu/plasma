"""The shipped Sysmon baseline config must log the events the rules need."""
import xml.etree.ElementTree as ET

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
