"""Fleet tests: inventory hygiene, transports (mocked + file), deterministic
joins, case hygiene, report rendering, CLI wiring.

No Windows host or pywinrm needed — remote pull is exercised through the
file transport and a monkeypatched WinRM responder; the join rules are pure
functions over normalized event dicts.
"""

import json
from pathlib import Path

import pytest

from plasma import fleet

ROOT = Path(__file__).resolve().parent.parent


def ts(offset_s, base="2026-10-19T09:00:00"):
    """ISO timestamp offset from base, UTC (Z-suffixed like endpoint data)."""
    from datetime import datetime, timedelta, timezone
    t = datetime.fromisoformat(base).replace(tzinfo=timezone.utc) + timedelta(seconds=offset_s)
    return t.isoformat().replace("+00:00", "Z")


def ev(host, user=None, ts_=None, **kw):
    row = {"ts": ts_ or ts(0), "host": host, "source": "whids", "kind": "alert",
           "event_id": 4624, "severity": "medium"}
    if user:
        row["user"] = user
    row.update(kw)
    return row


@pytest.fixture
def case(tmp_path):
    cd = fleet.init_case(tmp_path, "t1", window_seconds=1800)
    return cd


def _write_host_events(cd, host, rows):
    f = cd / "answers" / f"{host}.events.jsonl"
    f.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                 encoding="utf-8")


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------

def test_inventory_roundtrip(tmp_path):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": [
        {"name": "WS2", "transport": "winrm", "endpoint": "198.51.100.20",
         "username": "Administrator", "password_env": "WS2PW"},
        {"name": "LAB", "transport": "file", "events_path": "samples/plasma_events.jsonl"},
    ]}))
    entries = fleet.load_inventory(inv)
    assert [e["name"] for e in entries] == ["WS2", "LAB"]


@pytest.mark.parametrize("bad,why", [
    ({"hosts": [{"name": "a", "transport": "file"}]}, "file needs events_path"),
    ({"hosts": [{"name": "a", "transport": "winrm", "endpoint": "x",
                 "password": "hunter2", "password_env": "P"}]}, "inline password"),
    ({"hosts": [{"name": "a", "transport": "winrm", "endpoint": "x"}]}, "needs password_env"),
    ({"hosts": []}, "empty"),
    ({"hosts": [{"name": "bad name!", "transport": "file",
                 "events_path": "x"}]}, "bad name"),
    ({"hosts": [{"name": "a", "transport": "file", "events_path": "x"},
                {"name": "a", "transport": "file", "events_path": "y"}]}, "duplicate"),
])
def test_inventory_rejects(tmp_path, bad, why):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        fleet.load_inventory(inv)


# ---------------------------------------------------------------------------
# pull transports
# ---------------------------------------------------------------------------

def test_pull_file_transport(tmp_path):
    src = tmp_path / "src-events.jsonl"
    src.write_text("\n".join(json.dumps(ev(f"H{i}")) for i in range(10)))
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": [
        {"name": "LAB", "transport": "file", "events_path": str(src)}]}))
    out = fleet.pull(tmp_path, inv, "c1", cap=5)
    assert out["pulled"] == 1 and out["results"][0]["rows"] == 5
    rows = [json.loads(l) for l in
            (fleet.case_dir(tmp_path, "c1") / "answers" / "LAB.events.jsonl")
            .read_text().splitlines()]
    assert len(rows) == 5                                       # capped tail
    assert [r["host"] for r in rows] == [f"H{i}" for i in range(5, 10)]


def test_pull_winrm_transport_monkeypatched(tmp_path, monkeypatch):
    class FakeResult:
        status_code = 0
        std_out = ("\n".join(json.dumps(ev("WS2", user="EC2\\olu"))
                             for _ in range(3))).encode()
        std_err = b""
    class FakeSession:
        def __init__(self, *a, **k): pass
        def run_ps(self, cmd):
            assert "SecretPassword" not in cmd        # password never in command
            return FakeResult()
    fake_winrm = type("W", (), {"Session": FakeSession})
    monkeypatch.setitem(__import__("sys").modules, "winrm", fake_winrm)
    monkeypatch.setenv("WS2PW", "SecretPassword")

    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": [
        {"name": "WS2", "transport": "winrm", "endpoint": "10.0.0.9",
         "username": "Administrator", "password_env": "WS2PW"}]}))
    out = fleet.pull(tmp_path, inv, "c2")
    assert out["pulled"] == 1 and out["results"][0]["rows"] == 3
    # password hygiene: the case directory never contains the secret
    for f in (fleet.case_dir(tmp_path, "c2")).rglob("*"):
        if f.is_file():
            assert "SecretPassword" not in f.read_text(errors="ignore")


def test_pull_base64_read_path_preserves_unicode(tmp_path, monkeypatch):
    """Primary read is byte-exact base64: unicode in events survives the pipe."""
    import base64 as b64mod
    rows = [ev("WS2", user="EC2\\olu",
               description="em dash — stays intact")]
    payload = b64mod.b64encode(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                for r in rows).encode("utf-8")).decode()

    class FakeResult:
        status_code = 0
        std_out = ("PowerShell is ready!\n" + payload).encode()
        std_err = b""
    class FakeSession:
        def __init__(self, *a, **k): pass
        def run_ps(self, cmd):
            assert "ToBase64String" in cmd
            return FakeResult()
    fake_winrm = type("W", (), {"Session": FakeSession})
    monkeypatch.setitem(__import__("sys").modules, "winrm", fake_winrm)
    monkeypatch.setenv("WS2PW", "pw")

    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": [
        {"name": "WS2", "transport": "winrm", "endpoint": "10.0.0.9",
         "password_env": "WS2PW"}]}))
    out = fleet.pull(tmp_path, inv, "cb64")
    assert out["results"][0]["rows"] == 1
    assert out["results"][0]["read_via"] == "base64"
    got = [json.loads(l) for l in
           (fleet.case_dir(tmp_path, "cb64") / "answers" / "WS2.events.jsonl")
           .read_text().splitlines()]
    assert got[0]["description"] == "em dash — stays intact"


def test_rows_parser_survives_codepage_mangling():
    """A cp1252 round-trip turns an em dash into bytes that decode with an
    embedded double quote, breaking that JSON line; the parser must keep
    every healthy line instead of dying with it."""
    broken = '{"a": 1, "description": "x â€" y"}'
    text = "banner\n" + broken + "\n" + '{"a": 2}\n'
    rows = fleet._rows_from_text(text, 50)
    assert len(rows) == 1 and rows[0]["a"] == 2


def test_pull_winrm_missing_env_is_data(tmp_path, monkeypatch):
    monkeypatch.delenv("NO_SUCH_PW_VAR", raising=False)
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps({"hosts": [
        {"name": "WS2", "transport": "winrm", "endpoint": "10.0.0.9",
         "password_env": "NO_SUCH_PW_VAR"}]}))
    out = fleet.pull(tmp_path, inv, "c3")
    err = out["results"][0].get("error", "")
    assert ("environment variable" in err) or ("pywinrm" in err)


# ---------------------------------------------------------------------------
# deterministic joins
# ---------------------------------------------------------------------------

def test_correlate_lateral_hop(tmp_path):
    cd = fleet.init_case(tmp_path, "hop", window_seconds=1800)
    meta = json.loads((cd / "case.json").read_text())
    meta["host_addresses"] = {"WS1": "10.0.0.10", "WS2": "10.0.0.20"}
    (cd / "case.json").write_text(json.dumps(meta))
    _write_host_events(cd, "WS1", [ev(
        "WS1", user="CORP\\olu", ts_=ts(0), kind="auth",
        dest_ip="10.0.0.5", description="logon success type=3")])
    _write_host_events(cd, "WS2", [ev(
        "WS2", user="olu", ts_=ts(180), kind="auth",
        dest_ip="10.0.0.10", description="logon success type=10")])
    out = fleet.correlate(tmp_path, "hop")
    hops = [f for f in out["findings"] if f["type"] == "lateral_hop"]
    assert len(hops) == 1
    assert hops[0]["hosts"] == ["WS1", "WS2"]         # time-ordered
    assert hops[0]["score"] == 9 and hops[0]["linked"] is True
    assert out["verdict"] == "act now"


def test_correlate_lateral_without_source_link_is_not_act_now(tmp_path):
    """Same user, network logons, no address link: a lead, not proof."""
    cd = fleet.init_case(tmp_path, "hop2", window_seconds=1800)
    _write_host_events(cd, "WS1", [ev(
        "WS1", user="olu", ts_=ts(0), kind="auth", dest_ip="10.9.9.9",
        description="logon success type=3")])
    _write_host_events(cd, "WS2", [ev(
        "WS2", user="olu", ts_=ts(60), kind="auth", dest_ip="10.8.8.8",
        description="logon success type=3")])
    out = fleet.correlate(tmp_path, "hop2")
    hop = next(f for f in out["findings"] if f["type"] == "lateral_hop")
    assert hop["score"] == 7 and hop["linked"] is False
    assert out["verdict"] == "investigate"


def test_correlate_alert_rows_do_not_make_a_lateral_hop(tmp_path):
    """Process/alert rows carry users too; local execution is not a hop."""
    cd = fleet.init_case(tmp_path, "nothop", window_seconds=1800)
    _write_host_events(cd, "WS1", [ev("WS1", user="olu", kind="alert",
                                      dest_ip="10.0.0.1", ts_=ts(0))])
    _write_host_events(cd, "WS2", [ev("WS2", user="olu", kind="alert",
                                      dest_ip="10.0.0.1", ts_=ts(30))])
    out = fleet.correlate(tmp_path, "nothop")
    assert not [f for f in out["findings"] if f["type"] == "lateral_hop"]


def test_correlate_local_console_logons_do_not_make_a_hop(tmp_path):
    cd = fleet.init_case(tmp_path, "local", window_seconds=1800)
    _write_host_events(cd, "WS1", [ev("WS1", user="olu", kind="auth",
                                      description="logon success type=2", ts_=ts(0))])
    _write_host_events(cd, "WS2", [ev("WS2", user="olu", kind="auth",
                                      description="logon success type=2", ts_=ts(30))])
    out = fleet.correlate(tmp_path, "local")
    assert not [f for f in out["findings"] if f["type"] == "lateral_hop"]


def test_correlate_window_boundary(tmp_path):
    cd = fleet.init_case(tmp_path, "win", window_seconds=600)
    _write_host_events(cd, "WS1", [ev("WS1", user="bob", ts_=ts(0), kind="auth",
                                      dest_ip="10.0.0.1")])
    _write_host_events(cd, "WS2", [ev("WS2", user="bob", ts_=ts(601), kind="auth",
                                      dest_ip="10.0.0.1")])
    out = fleet.correlate(tmp_path, "win")
    assert [f for f in out["findings"] if f["type"] == "lateral_hop"] == []


def test_correlate_same_user_one_host_is_clean(tmp_path):
    cd = fleet.init_case(tmp_path, "one", window_seconds=1800)
    _write_host_events(cd, "WS1", [ev("WS1", user="bob", ts_=ts(0), kind="auth",
                                      dest_ip="10.0.0.1"),
                                   ev("WS1", user="bob", ts_=ts(60), kind="auth",
                                      dest_ip="10.0.0.1")])
    out = fleet.correlate(tmp_path, "one")
    assert out["findings"] == [] and out["verdict"] == "clean"


def test_correlate_shared_hash_domain_ip(tmp_path):
    cd = fleet.init_case(tmp_path, "ind")
    h = "9f2c8e14d7b3a6c5e8f1042736b9adc2e5f7081a3b6d9c4e7f2a5b8d1c4e7f09"
    _write_host_events(cd, "WS1", [
        ev("WS1", file_hash=h, dns_query="c2.bad.example", dest_ip="185.220.101.4")])
    _write_host_events(cd, "WS2", [
        ev("WS2", file_hash=h),
        ev("WS2", dns_query="c2.bad.example"),
        ev("WS2", dest_ip="185.220.101.4")])
    out = fleet.correlate(tmp_path, "ind")
    types = {f["type"] for f in out["findings"]}
    assert types == {"shared_hash", "shared_domain", "shared_ip"}
    shared_hash = next(f for f in out["findings"] if f["type"] == "shared_hash")
    assert shared_hash["hosts"] == ["WS1", "WS2"] and shared_hash["score"] == 8


def test_correlate_canary_anywhere_is_ten(tmp_path):
    cd = fleet.init_case(tmp_path, "can", canaries=["canary-quiet"])
    _write_host_events(cd, "WS3", [ev("WS3", user="CORP\\canary-quiet", ts_=ts(5))])
    out = fleet.correlate(tmp_path, "can")
    assert out["findings"][0]["type"] == "canary_tripped"
    assert out["findings"][0]["score"] == 10
    assert out["verdict"] == "act now"


def test_correlate_machine_and_system_accounts_ignored(tmp_path):
    cd = fleet.init_case(tmp_path, "mach")
    _write_host_events(cd, "WS1", [ev("WS1", user="WS1$", ts_=ts(0), kind="auth"),
                                   ev("WS1", user="SYSTEM", ts_=ts(1), kind="auth"),
                                   ev("WS1", user="-", ts_=ts(2), kind="auth")])
    _write_host_events(cd, "WS2", [ev("WS2", user="WS2$", ts_=ts(3), kind="auth"),
                                   ev("WS2", user="SYSTEM", ts_=ts(4), kind="auth")])
    out = fleet.correlate(tmp_path, "mach")
    assert out["findings"] == []


def test_correlate_blind_host_from_attest_answer(tmp_path):
    cd = fleet.init_case(tmp_path, "blind")
    (cd / "answers" / "WS9.attest.json").write_text(json.dumps(
        {"question": "attest", "blind_count": 2,
         "blind_subcategories": ["Registry", "File Share"],
         "whids_service": "Running"}))
    out = fleet.correlate(tmp_path, "blind")
    assert out["findings"][0]["type"] == "blind_host"
    assert out["findings"][0]["score"] == 8


def test_correlate_missing_case_is_helpful(tmp_path):
    out = fleet.correlate(tmp_path, "ghost")
    assert "error" in out and "plasma fleet pull" in out["hint"]


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def test_report_renders_and_persists(tmp_path):
    cd = fleet.init_case(tmp_path, "rep")
    meta = json.loads((cd / "case.json").read_text())
    meta["host_addresses"] = {"WS1": "10.0.0.10"}
    (cd / "case.json").write_text(json.dumps(meta))
    _write_host_events(cd, "WS1", [ev("WS1", user="bob", ts_=ts(0), kind="auth",
                                      dest_ip="10.0.0.5")])
    _write_host_events(cd, "WS2", [ev("WS2", user="bob", ts_=ts(30), kind="auth",
                                      dest_ip="10.0.0.10")])
    fleet.correlate(tmp_path, "rep")
    out = fleet.report(tmp_path, "rep")
    md = Path(out["report"]).read_text()
    assert "# Plasma fleet case: rep" in md
    assert "lateral_hop" in md and "act now" in md
    assert "bob" in md


def test_report_without_correlate_is_data(tmp_path):
    fleet.init_case(tmp_path, "empty")
    assert "error" in fleet.report(tmp_path, "empty")


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_cli_fleet_group_wiring():
    from plasma import cli
    p = cli.build_parser()
    p.parse_args(["fleet", "pull", "--inventory", "i.json", "--case", "c"])
    p.parse_args(["fleet", "correlate", "--case", "c"])
    p.parse_args(["fleet", "report", "--case", "c"])
    p.parse_args(["fleet", "scan", "--inventory", "i.json", "--case", "c"])


def test_shared_public_indicator_without_a_signal_is_suppressed(tmp_path):
    """Two hosts hitting the same CDN is background, not lateral movement."""
    cd = fleet.init_case(tmp_path, "noise")
    for host in ("WS1", "WS2"):
        _write_host_events(cd, host, [
            ev(host, dns_query="cdn.example.net", dest_ip="93.184.216.34",
               severity="info", score=0.1, ts_=ts(0))])
    out = fleet.correlate(tmp_path, "noise")
    assert not [f for f in out["findings"]
                if f["type"] in ("shared_domain", "shared_ip")]


def test_shared_public_indicator_with_one_scored_row_is_kept(tmp_path):
    cd = fleet.init_case(tmp_path, "signal")
    _write_host_events(cd, "WS1", [
        ev("WS1", dns_query="c2.bad.example", severity="critical", score=0.9,
           ts_=ts(0))])
    _write_host_events(cd, "WS2", [
        ev("WS2", dns_query="c2.bad.example", severity="info", score=0.1,
           ts_=ts(30))])
    out = fleet.correlate(tmp_path, "signal")
    assert [f for f in out["findings"] if f["type"] == "shared_domain"]
