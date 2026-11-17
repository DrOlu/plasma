"""Payload regressions for actions that touch the Administrators group."""
from plasma import actuate


def test_snapshot_uses_net_localgroup_not_get_localgroupmember():
    payload, undo, guard = actuate._build_snapshot()
    assert "net.exe localgroup Administrators" in payload
    assert "Get-LocalGroupMember -Group 'Administrators'" not in payload
    assert undo is None
    assert "Test-Path" in guard


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
