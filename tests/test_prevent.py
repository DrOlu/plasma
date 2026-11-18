"""Tier 1 prevention: generation, validation, plan gate, rollback."""
import json

import pytest

from plasma import prevent

GUID = "b2b3f03d-6a92-4b3f-8c0e-0a2f3d9a1c11"


@pytest.fixture
def fake_ps(monkeypatch):
    calls = []

    def run(script, timeout=120):
        calls.append(script)
        if "Get-AppLockerPolicy -Effective -Xml" in script and "WriteAllText" in script:
            return 0, "C:\\ProgramData\\Plasma\\prevent-backups\\applocker-1.xml"
        if "Set-AppLockerPolicy" in script:
            return 0, json.dumps({"applied": True, "rules": 4, "audit": True,
                                  "sha": "x"})
        if "Add-MpPreference" in script:
            return 0, json.dumps({"applied": True, "ids": [GUID],
                                  "actions": ["AuditMode"]})
        if "Get-MpPreference" in script:
            return 0, json.dumps({"ids": [GUID], "actions": ["Disabled"]})
        if "RunAsPPL" in script:
            return 0, json.dumps({"applied": True, "RunAsPPL": 1,
                                  "reboot_required": True})
        if "Get-NetFirewallRule" in script:
            return 0, json.dumps({"applied": True, "rules": 3})
        return 0, "{}"

    monkeypatch.setattr(prevent, "_ps", run)
    return calls


def test_applocker_audit_is_the_default_and_keeps_admin_access():
    xml = prevent.applocker_xml("audit")
    assert 'EnforcementMode="AuditOnly"' in xml
    assert "%WINDIR%\\*" in xml and "%PROGRAMFILES%\\*" in xml
    assert "S-1-5-32-544" in xml          # Administrators keep a path in


def test_applocker_enforce_mode_and_extra_paths():
    xml = prevent.applocker_xml("enforce", [r"D:\Apps\*"])
    assert 'EnforcementMode="Enabled"' in xml and r"D:\Apps\*" in xml


@pytest.mark.parametrize("bad", ['<script>', 'a"b', ""])
def test_applocker_rejects_unsafe_paths(bad):
    with pytest.raises(ValueError):
        prevent.applocker_xml("audit", [bad])


def test_applocker_apply_requires_a_matching_plan(tmp_path, fake_ps):
    dry = prevent.applocker(tmp_path, mode="audit")
    assert dry["status"] == "dry-run" and dry["id"] == 1
    refused = prevent.applocker(tmp_path, mode="audit", apply=True)
    assert refused["code"] == "REFUSED"
    wrong = prevent.applocker(tmp_path, mode="enforce", apply=True, plan=1,
                              reason="test")
    assert wrong["code"] == "REFUSED"     # digest differs from the dry-run
    done = prevent.applocker(tmp_path, mode="audit", apply=True, plan=1,
                             reason="test")
    assert done["status"] == "applied"
    assert done["verification"]["rules"] == 4


def test_applocker_reason_is_mandatory(tmp_path, fake_ps):
    prevent.applocker(tmp_path, mode="audit")
    out = prevent.applocker(tmp_path, mode="audit", apply=True, plan=1)
    assert out["code"] == "REFUSED" and "reason" in out["error"]


def test_egress_needs_an_allowlist_and_validates_addresses():
    with pytest.raises(ValueError):
        prevent.egress_payload([])
    assert prevent.validate_allow(["10.0.0.0/8", "1.2.3.4:443"]) == [
        {"remote": "10.0.0.0/8", "port": None},
        {"remote": "1.2.3.4", "port": 443}]
    for bad in ["999.1.1.1", "1.2.3.4:70000", "abc", "1.2.3.4; x",
                "10.0.0.0/99"]:
        with pytest.raises(ValueError):
            prevent.validate_allow([bad])


def test_egress_payload_blocks_after_allowing():
    payload = prevent.egress_payload(["1.2.3.4:443"])
    assert payload.index("Egress-Allow-0") < payload.index("Egress-Block")
    assert "-RemotePort 443" in payload


def test_egress_apply_through_plan(tmp_path, fake_ps):
    dry = prevent.egress(tmp_path, ["1.2.3.4:443"])
    done = prevent.egress(tmp_path, ["1.2.3.4:443"], apply=True, plan=dry["id"],
                          reason="test")
    assert done["status"] == "applied"
    preview = prevent.rollback(tmp_path, done["id"])
    roll = prevent.rollback(tmp_path, done["id"], apply=True,
                            plan=preview["plan"], reason="test")
    assert roll["rolled_back"] is True


def test_asr_validates_guids_and_maps_actions():
    assert prevent.parse_asr(GUID, "Audit") == [GUID]
    assert prevent.parse_asr([GUID], "Block") == [GUID]
    with pytest.raises(ValueError):
        prevent.parse_asr("not-a-guid", "Audit")
    with pytest.raises(ValueError):
        prevent.parse_asr(GUID, "Sometimes")


def test_asr_apply_and_rollback(tmp_path, fake_ps):
    dry = prevent.asr([GUID], action="Audit", root=tmp_path)
    assert dry["status"] == "dry-run"
    done = prevent.asr([GUID], action="Audit", root=tmp_path, apply=True,
                       plan=dry["id"], reason="test")
    assert done["status"] == "applied"
    assert done["undo"]["previous"][GUID] == "Disabled"
    preview = prevent.rollback(tmp_path, done["id"])
    roll = prevent.rollback(tmp_path, done["id"], apply=True,
                            plan=preview["plan"], reason="test")
    assert roll["rolled_back"] is True


def test_lsa_is_reversible(tmp_path, fake_ps):
    dry = prevent.lsa(root=tmp_path)
    assert dry["status"] == "dry-run" and "RunAsPPL" in dry["preview"]
    done = prevent.lsa(root=tmp_path, apply=True, plan=dry["id"], reason="test")
    assert done["status"] == "applied"
    assert done["verification"]["reboot_required"] is True


def test_reused_plan_is_refused(tmp_path, fake_ps):
    dry = prevent.lsa(root=tmp_path)
    prevent.lsa(root=tmp_path, apply=True, plan=dry["id"], reason="test")
    again = prevent.lsa(root=tmp_path, apply=True, plan=dry["id"], reason="test")
    assert again["code"] == "REFUSED" and "already been used" in again["error"]


def test_status_surfaces_what_is_not_available(monkeypatch):
    monkeypatch.setattr(prevent, "_ps_json", lambda s, timeout=120: (
        {"defender": None, "applocker_rules": 0, "wdac_policies": 0,
         "firewall": ["Domain:Allow"], "asr_ids": [GUID],
         "asr_actions": ["AuditMode"]}, None))
    out = prevent.status()
    assert out["asr"] == {GUID: "AuditMode"}
    assert "asr_ids" not in out


def test_applocker_verification_uses_local_policy_not_effective():
    """Field bug: -Effective lagged the write and reported zero rules."""
    assert "Get-AppLockerPolicy -Local" in prevent._APPLOCKER_APPLY_PS
    assert "Get-AppLockerPolicy -Effective" not in prevent._APPLOCKER_APPLY_PS


def test_applocker_rollback_refuses_without_a_backup():
    assert "refusing to clear all local rules" in prevent._APPLOCKER_ROLLBACK_PS
    assert "<AppLockerPolicy Version=\"1\" />" not in prevent._APPLOCKER_ROLLBACK_PS


def test_status_ignores_null_asr_entries(monkeypatch):
    monkeypatch.setattr(prevent, "_ps_json", lambda s, timeout=120: (
        {"asr_ids": [None], "asr_actions": []}, None))
    assert prevent.status()["asr"] == {}


def test_egress_warns_when_dns_is_not_allowlisted():
    warnings = prevent.egress_warnings(["10.0.0.0/8"])
    assert warnings and "port-53" in warnings[0]
    assert prevent.egress_warnings(["10.0.0.0/8", "10.0.0.2:53"]) == []
