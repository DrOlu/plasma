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


def _trace(ts, script, process=r"C:\Users\sam\loader.exe", self_=0):
    if script == "inject-rwx":
        detail = (f'dtrace inject-rwx: inject_rwx {{"protect": "0x40", '
                  f'"self": {self_}, "score": 8, "tid": 11}}')
    else:
        detail = f'dtrace {script}: probe {{"tid": 11}}'
    return _row(ts, kind="trace", source="dtrace", process=process,
                description=detail)


def test_injection_chain_fires_on_rwx_then_remote_thread():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx"),
        _trace("2026-11-05T11:01:00Z", "inject-remote-thread"),
    ]
    findings = chain.scan(rows)
    injection = [f for f in findings if f["type"] == "chain_injection_chain"]
    assert injection, findings
    assert injection[0]["score"] == 9
    assert injection[0]["steps"] == 2


def test_injection_chain_ignores_self_rwx():
    """A process flipping its own page to RWX is JIT warm-up, not injection."""
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx", self_=1),
        _trace("2026-11-05T11:01:00Z", "inject-remote-thread"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_chain"]


def test_injection_chain_binds_both_halves_to_one_image():
    """Remote thread creation is common system noise; the chain is only a
    story when the same image did both."""
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx", process=r"C:\x\loader.exe"),
        _trace("2026-11-05T11:01:00Z", "inject-remote-thread",
               process=r"C:\Windows\System32\svchost.exe"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_chain"]


def test_injection_chain_respects_the_gap_window():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx"),
        _trace("2026-11-05T11:05:00Z", "inject-remote-thread"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_chain"]


def test_injection_chain_needs_both_halves():
    for script in ("inject-rwx", "inject-remote-thread"):
        rows = [_trace("2026-11-05T11:00:00Z", script)]
        assert not [f for f in chain.scan(rows)
                    if f["type"] == "chain_injection_chain"]


def test_injection_apc_chain_fires_on_cross_process_rwx_then_apc():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx"),
        _trace("2026-11-05T11:00:20Z", "inject-apc"),
    ]
    findings = [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_apc_chain"]
    assert findings and findings[0]["score"] == 9


def test_injection_apc_chain_ignores_self_rwx():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx", self_=1),
        _trace("2026-11-05T11:00:20Z", "inject-apc"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_apc_chain"]


def test_injection_apc_chain_respects_the_short_gap():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx"),
        _trace("2026-11-05T11:01:00Z", "inject-apc"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_apc_chain"]


def test_injection_apc_chain_binds_one_image():
    rows = [
        _trace("2026-11-05T11:00:00Z", "inject-rwx", process=r"C:\x\loader.exe"),
        _trace("2026-11-05T11:00:20Z", "inject-apc",
               process=r"C:\Windows\System32\svchost.exe"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_injection_apc_chain"]


def test_kerberos_spray_then_tgt_success_fires():
    rows = [_auth(f"2026-11-05T04:{m:02d}:00Z", 4771, "olu@CORP.LOCAL")
            for m in range(5)]
    rows.append(_auth("2026-11-05T04:10:00Z", 4768, "olu@CORP.LOCAL"))
    findings = chain.scan(rows)
    k = [f for f in findings if f["type"] == "chain_kerberos_brute_force"]
    assert k and k[0]["score"] == 9
    assert k[0]["users"] == ["olu"]


def test_kerberos_spray_needs_the_burst_and_the_same_account():
    rows = [_auth(f"2026-11-05T04:{m:02d}:00Z", 4771, "olu@CORP.LOCAL")
            for m in range(4)]
    rows.append(_auth("2026-11-05T04:10:00Z", 4768, "olu@CORP.LOCAL"))
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_kerberos_brute_force"]

    rows = [_auth(f"2026-11-05T05:{m:02d}:00Z", 4771, "olu@CORP.LOCAL")
            for m in range(5)]
    rows.append(_auth("2026-11-05T05:10:00Z", 4768, "someone.else@CORP.LOCAL"))
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_kerberos_brute_force"]


def _trace_row(ts, script, process="loader.exe"):
    return _row(ts, kind="trace", process=process,
                description=f"dtrace {script}: event")


def test_hollowing_chain_needs_unmap_write_and_thread():
    rows = [_trace_row("2026-11-05T12:00:00Z", "inject-hollow"),
            _trace_row("2026-11-05T12:00:20Z", "inject-write"),
            _trace_row("2026-11-05T12:00:40Z", "inject-remote-thread")]
    found = [f for f in chain.scan(rows)
             if f["type"] == "chain_injection_hollow_chain"]
    assert found and found[0]["score"] == 9
    assert not [f for f in chain.scan(rows[:2])
                if f["type"] == "chain_injection_hollow_chain"]


def test_section_and_write_chains_require_a_remote_thread():
    for script, name in (("inject-section", "injection_section_chain"),
                         ("inject-write", "injection_write_chain")):
        rows = [_trace_row("2026-11-05T12:00:00Z", script),
                _trace_row("2026-11-05T12:00:20Z", "inject-remote-thread")]
        found = [f for f in chain.scan(rows) if f["type"] == f"chain_{name}"]
        assert found and found[0]["score"] == 9
        assert not [f for f in chain.scan(rows[:1])
                    if f["type"] == f"chain_{name}"]


def test_hijack_chain_binds_the_same_image():
    rows = [_trace_row("2026-11-05T12:00:00Z", "inject-hijack"),
            _trace_row("2026-11-05T12:00:20Z", "inject-remote-thread")]
    found = [f for f in chain.scan(rows)
             if f["type"] == "chain_injection_hijack_chain"]
    assert found and found[0]["score"] == 8
    other = [_trace_row("2026-11-05T12:00:00Z", "inject-hijack", "a.exe"),
             _trace_row("2026-11-05T12:00:20Z", "inject-remote-thread", "b.exe")]
    assert not [f for f in chain.scan(other)
                if f["type"] == "chain_injection_hijack_chain"]


def test_persistence_after_privilege_matches_cmdline():
    """Real 4688 rows carry the command in cmdline, not description. The
    chain must read both or the story is invisible on a live host."""
    rows = [
        _row("2026-11-05T03:00:00Z", kind="process",
             process=r"C:\Windows\System32\net.exe", user="admin",
             description="process created by CORP\\Administrator parent=cmd.exe image=net.exe",
             cmdline="net user backdoor P@ss /add"),
        _row("2026-11-05T03:05:00Z", kind="process",
             process=r"C:\Windows\System32\schtasks.exe", user="admin",
             description="process created by CORP\\Administrator parent=cmd.exe image=schtasks.exe",
             cmdline="schtasks /create /tn Update /sc onstart"),
    ]
    findings = chain.scan(rows)
    assert [f for f in findings if f["type"] == "chain_persistence_after_privilege"]


def test_persistence_chain_ignores_benign_cmdline():
    rows = [
        _row("2026-11-05T03:00:00Z", kind="process",
             process=r"C:\Windows\System32\net.exe", user="admin",
             description="process created by CORP\\Administrator parent=cmd.exe image=net.exe",
             cmdline="net user /?"),
        _row("2026-11-05T03:05:00Z", kind="process",
             process=r"C:\Windows\System32\schtasks.exe", user="admin",
             description="process created by CORP\\Administrator parent=cmd.exe image=schtasks.exe",
             cmdline="schtasks /query"),
    ]
    assert not [f for f in chain.scan(rows)
                if f["type"] == "chain_persistence_after_privilege"]
