"""Chain detection: deterministic story-level matches over event rows."""
import json

from plasma import chain


def _row(ts, kind="process", **kw):
    return {"ts": ts, "kind": kind, **kw}


PHISH_STORY = [
    _row("2026-11-05T10:00:00Z", kind="process",
         process=r"C:\Program Files\Microsoft Office\winword.exe", user="sam"),
    _row("2026-11-05T10:01:30Z", kind="process",
         process=r"C:\Windows\System32\windowspowershell\v1.0\powershell.exe",
         user="sam", description=r"powershell -enc SQBFAFgA"),
    _row("2026-11-05T10:02:30Z", kind="network",
         dest_ip="203.0.113.9", user="sam"),
]


def test_phish_chain_fires_on_in_order_story():
    findings = chain.scan(PHISH_STORY)
    phish = [f for f in findings if f["type"] == "chain_phish_spawn_chain"]
    assert phish, findings
    f = phish[0]
    assert f["score"] == 9
    assert f["steps"] == 3
    assert f["users"] == ["sam"]
    assert f["span_minutes"] == 2


def test_phish_chain_needs_the_middle_step():
    without_ps = [PHISH_STORY[0], PHISH_STORY[2]]
    findings = chain.scan(without_ps)
    assert not [f for f in findings if f["type"] == "chain_phish_spawn_chain"]


def test_phish_chain_respects_time_order():
    """Chains match on timestamp order, not file order — a story told
    backwards in time (egress BEFORE spawn) is not the story."""
    backwards = [
        dict(PHISH_STORY[2], ts="2026-11-05T10:00:00Z"),
        dict(PHISH_STORY[1], ts="2026-11-05T10:01:30Z"),
        dict(PHISH_STORY[0], ts="2026-11-05T10:02:30Z"),
    ]
    findings = chain.scan(backwards)
    assert not [f for f in findings if f["type"] == "chain_phish_spawn_chain"]


def test_phish_chain_respects_gap_window():
    spread = [
        PHISH_STORY[0],
        _row("2026-11-05T10:20:00Z", kind="process",
             process=r"C:\Windows\System32\powershell.exe", user="sam"),
        _row("2026-11-05T10:25:00Z", kind="network", dest_ip="203.0.113.9",
             user="sam"),
    ]
    findings = chain.scan(spread)
    assert not [f for f in findings if f["type"] == "chain_phish_spawn_chain"]
    # ...but an explicitly wider chain definition catches it (a built-in's
    # own gap_seconds is deliberate and wins over the scan default)
    wide = dict(chain.BUILTIN_CHAINS[0], gap_seconds=1800)
    findings = chain.scan(spread, chains=[wide])
    assert [f for f in findings if f["type"] == "chain_phish_spawn_chain"]


def _auth(ts, eid, user):
    return _row(ts, kind="auth", event_id=eid, user=user,
                description=f"logon {'success' if eid == 4624 else 'FAILED'}")


def test_brute_force_success_fires_after_burst():
    rows = [_auth(f"2026-11-05T02:{m:02d}:00Z", 4625, "bob") for m in range(5)]
    rows.append(_auth("2026-11-05T02:10:00Z", 4624, "bob"))
    findings = chain.scan(rows)
    bf = [f for f in findings if f["type"] == "chain_brute_force_success"]
    assert bf and bf[0]["score"] == 8


def test_brute_force_needs_the_full_burst():
    rows = [_auth(f"2026-11-05T02:{m:02d}:00Z", 4625, "bob") for m in range(4)]
    rows.append(_auth("2026-11-05T02:10:00Z", 4624, "bob"))
    findings = chain.scan(rows)
    assert not [f for f in findings if f["type"] == "chain_brute_force_success"]


def test_persistence_after_privilege_fires():
    rows = [
        _row("2026-11-05T03:00:00Z", kind="process",
             process=r"C:\Windows\System32\net1.exe", user="admin",
             description="net1 user backdoor P@ss /add"),
        _row("2026-11-05T03:05:00Z", kind="process",
             process=r"C:\Windows\System32\schtasks.exe", user="admin",
             description="schtasks /create /tn Update /sc onstart"),
    ]
    findings = chain.scan(rows)
    assert [f for f in findings if f["type"] == "chain_persistence_after_privilege"]


def test_unrelated_rows_do_not_match():
    rows = [
        _row("2026-11-05T09:00:00Z", kind="dns", dns_query="portal.hyperspaceng.com"),
        _row("2026-11-05T09:01:00Z", kind="process",
             process=r"C:\Windows\System32\notepad.exe", user="sam"),
        _row("2026-11-05T09:02:00Z", kind="auth", event_id=4624, user="sam",
             description="logon success"),
    ]
    assert chain.scan(rows) == []


def test_scan_store_reads_tail_and_ignores_noise(tmp_path):
    store = tmp_path / "events.jsonl"
    lines = ["banner noise", "not json {"]
    lines += [json.dumps(r) for r in PHISH_STORY]
    store.write_text("\n".join(lines) + "\n")
    result = chain.scan_store(store)
    assert result["scanned_rows"] == 3
    assert result["top_score"] == 9
    assert result["findings"][0]["type"] == "chain_phish_spawn_chain"


def test_scan_store_missing_file_is_data(tmp_path):
    result = chain.scan_store(tmp_path / "nope.jsonl")
    assert "error" in result and result["findings"] == []
