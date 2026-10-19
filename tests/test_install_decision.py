"""Installer WHIDS/Sysmon decision tests: the incubate-two-paths logic.

The decision function is pure; the network probe takes an injected prober,
so no Windows host or real internet is needed.
"""

from plasma.cli import internet_available, whids_install_decision as decide


# ---------------------------------------------------------------------------
# decision matrix
# ---------------------------------------------------------------------------

def test_full_when_sysmon_present():
    d = decide(sysmon_present=True, whids_present=False, payload_present=True,
               skip_whids=False)
    assert d["decision"] == "full" and not d["degraded"]


def test_already_present_when_whids_running():
    d = decide(sysmon_present=True, whids_present=True, payload_present=True,
               skip_whids=False)
    assert d["decision"] == "already_present" and not d["degraded"]


def test_whids_present_but_sysmon_absent_is_a_repair():
    """WHIDS cannot start without Sysmon: the installer must acquire Sysmon,
    not honor the broken state as already_present (WS1 field lesson)."""
    d = decide(sysmon_present=False, whids_present=True, payload_present=True,
               skip_whids=False, internet_ok=True)
    assert d["decision"] == "attempt_sysmon_install"
    d2 = decide(sysmon_present=False, whids_present=True, payload_present=True,
                skip_whids=False, sysmon_install_ok=True)
    assert d2["decision"] == "full" and d2.get("repair") is True
    d3 = decide(sysmon_present=False, whids_present=True, payload_present=True,
                skip_whids=False, internet_ok=False)
    assert d3["decision"] == "skipped" and "WHIDS present but cannot start" in d3["reason"]


def test_skip_flag_forces_minimal():
    d = decide(sysmon_present=True, whids_present=False, payload_present=True,
               skip_whids=True)
    assert d["decision"] == "skipped" and d["degraded"]
    assert "--skip-whids" in d["reason"]


def test_no_payload_forces_minimal():
    d = decide(sysmon_present=True, whids_present=False, payload_present=False,
               skip_whids=False)
    assert d["decision"] == "skipped" and d["degraded"]
    assert "payload" in d["reason"]


def test_no_internet_degrades_to_minimal():
    d = decide(sysmon_present=False, whids_present=False, payload_present=True,
               skip_whids=False, internet_ok=False)
    assert d["decision"] == "skipped" and d["degraded"]
    assert "internet" in d["reason"]


def test_failed_sysmon_download_degrades():
    d = decide(sysmon_present=False, whids_present=False, payload_present=True,
               skip_whids=False, sysmon_install_ok=False)
    assert d["decision"] == "skipped" and d["degraded"]
    assert "download" in d["reason"]


def test_successful_sysmon_download_upgrades_to_full():
    d = decide(sysmon_present=False, whids_present=False, payload_present=True,
               skip_whids=False, sysmon_install_ok=True)
    assert d["decision"] == "full" and not d["degraded"]
    assert "accepteula" in d.get("sysmon", "")


def test_attempt_is_returned_when_internet_ok_and_sysmon_absent():
    d = decide(sysmon_present=False, whids_present=False, payload_present=True,
               skip_whids=False, internet_ok=True)
    assert d["decision"] == "attempt_sysmon_install"


# ---------------------------------------------------------------------------
# internet probe
# ---------------------------------------------------------------------------

def test_internet_probe_ok():
    assert internet_available(prober=lambda url: url.startswith("https://download"))


def test_internet_probe_down():
    def _fail(url):
        raise OSError("no route")
    assert internet_available(prober=_fail) is False
