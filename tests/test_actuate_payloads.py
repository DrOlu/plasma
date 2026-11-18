"""Payload regressions for actions that touch the Administrators group."""
import pytest

from plasma import actuate


def test_process_guard_payload_does_not_emit_the_cim_object(monkeypatch):
    """`($p = Get-CimInstance ...)` prints the whole object, so the guard
    compared table text instead of the process name and allowed LSASS."""
    seen = {}

    def fake_run(payload, timeout=30):
        seen["payload"] = payload
        return {"output": "csrss.exe", "rc": 0}

    monkeypatch.setattr(actuate, "_run", fake_run)
    with pytest.raises(PermissionError):
        actuate._g_process("580")
    assert "($p =" not in seen["payload"]
    assert "$p = Get-CimInstance" in seen["payload"]


def test_snapshot_uses_net_localgroup_not_get_localgroupmember():
    payload, undo, guard = actuate._build_snapshot()
    assert "net.exe localgroup Administrators" in payload
    assert "Get-LocalGroupMember -Group 'Administrators'" not in payload
    assert undo is None
    assert "Get-ChildItem" in guard and "snapshot-" in guard


def test_remove_admin_uses_net_localgroup():
    payload, undo, guard = actuate._build_remove_admin("PlasmaDrill_User")
    assert "net.exe localgroup Administrators" in payload
    assert "net.exe localgroup Administrators" in undo
    assert "Get-LocalGroupMember -Group 'Administrators'" not in payload
    assert "Get-LocalGroupMember -Group 'Administrators'" not in undo
    assert "$admins -contains" in guard


def test_run_key_path_is_case_insensitive():
    """The canonical registry spelling is `Software`, not `SOFTWARE`; the
    allowlist must accept both or remove_run_key refuses every real key."""
    actuate._v_run_key(r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    actuate._v_run_key(r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")


def test_pending_approvals_hides_terminal_outcomes(tmp_path):
    from plasma import ledger
    ledger.append(tmp_path, {
        "kind": "action", "decision": "approval_required",
        "outcome": "approval_invalid", "tool": "isolate_host",
        "args_sha256": "x", "seq": 1,
    })
    assert ledger.pending_approvals(tmp_path) == []
