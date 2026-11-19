"""Native canary tokens: registry, DNS matching, HTTP collector, watch."""

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from plasma import canary_tokens, enforce, health, watch


def _store(root: Path) -> Path:
    path = root / "data" / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _dns_row(fqdn, **over):
    row = {
        "ts": "2026-11-19T10:00:00.000Z",
        "host": "WS1",
        "source": "sysmon",
        "kind": "dns",
        "event_id": 22,
        "severity": "info",
        "user": "CORP\\olu",
        "process": "powershell.exe",
        "pid": 1234,
        "dns_query": fqdn,
    }
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# registry and artifacts
# ---------------------------------------------------------------------------

def test_create_dns_token_and_validate(tmp_path):
    token = canary_tokens.create(tmp_path, "dns", domain="Assets.Internal.")
    assert token["kind"] == "dns"
    assert token["domain"] == "assets.internal"
    assert token["fqdn"].endswith(".assets.internal")
    assert token["fqdn"].split(".")[0] == token["id"]
    listed = canary_tokens.list_tokens(tmp_path)
    assert listed["count"] == 1 and listed["tokens"][0]["id"] == token["id"]
    assert canary_tokens.dns_domains(tmp_path) == ["assets.internal"]


@pytest.mark.parametrize("domain", [
    "", "single", "bad_label.example", "http://assets.internal",
    "assets.internal/path", "assets..internal",
])
def test_invalid_dns_domain_rejected(tmp_path, domain):
    with pytest.raises(ValueError):
        canary_tokens.create(tmp_path, "dns", domain=domain)


def test_create_http_token_writes_url_shortcut(tmp_path):
    artifact_dir = tmp_path / "artifacts"
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088",
        out=artifact_dir, name="Intranet_Portal.url")
    assert token["url"] == f"http://collector:8088/t/{token['id']}"
    path = Path(token["artifact"])
    assert path.exists() and path.name == "Intranet_Portal.url"
    body = path.read_text(encoding="utf-8")
    assert "[InternetShortcut]" in body
    assert token["url"] in body
    assert "canary" not in body.lower()


@pytest.mark.parametrize("base", [
    "ftp://collector:8088", "http://user:pass@collector:8088",
    "http://collector:8088/path", "http://collector:8088?x=1",
    "http://collector:99999", "not-a-url",
])
def test_invalid_http_base_url_rejected(tmp_path, base):
    with pytest.raises(ValueError):
        canary_tokens.create(tmp_path, "http", base_url=base)


def test_remove_token_and_artifact(tmp_path):
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088")
    artifact = Path(token["artifact"])
    assert artifact.exists()
    result = canary_tokens.remove(tmp_path, token["id"], delete_artifact=True)
    assert result["removed"] == token["id"]
    assert result["artifact_removed"] is True
    assert not artifact.exists()
    assert canary_tokens.list_tokens(tmp_path)["count"] == 0


def test_remove_does_not_delete_artifact_outside_root(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.url"
    outside.write_text("[InternetShortcut]\nURL=http://example/\n")
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088",
        out=outside)
    result = canary_tokens.remove(tmp_path, token["id"], delete_artifact=True)
    assert result["artifact_removed"] is False
    assert outside.exists()


def test_status_reports_tokens_and_missing_artifacts(tmp_path):
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088")
    Path(token["artifact"]).unlink()
    status = canary_tokens.status(tmp_path)
    assert status["tokens"] == 1
    assert status["by_kind"] == {"http": 1}
    assert status["missing_artifacts"][0]["id"] == token["id"]


# ---------------------------------------------------------------------------
# DNS matching
# ---------------------------------------------------------------------------

def test_dns_hit_appends_canary_event_once(tmp_path):
    token = canary_tokens.create(tmp_path, "dns", domain="assets.internal")
    store = _store(tmp_path)
    store.write_text(json.dumps(_dns_row(token["fqdn"])) + "\n")
    first = canary_tokens.collect_dns_hits(tmp_path, store)
    assert first["appended"] == 1
    rows = [json.loads(line) for line in store.read_text().splitlines()]
    assert rows[-1]["source"] == "canary"
    assert rows[-1]["alert_id"] == f"canary:dns:{token['id']}"
    assert rows[-1]["score"] == 0.8
    assert rows[-1]["kind"] == "alert"
    second = canary_tokens.collect_dns_hits(tmp_path, store)
    assert second["appended"] == 0


def test_dns_match_is_case_insensitive_with_trailing_dot(tmp_path):
    token = canary_tokens.create(tmp_path, "dns", domain="assets.internal")
    store = _store(tmp_path)
    store.write_text(json.dumps(_dns_row(token["fqdn"].upper() + ".")) + "\n")
    assert canary_tokens.collect_dns_hits(tmp_path, store)["appended"] == 1


def test_dns_ignores_unrelated_queries(tmp_path):
    token = canary_tokens.create(tmp_path, "dns", domain="assets.internal")
    store = _store(tmp_path)
    store.write_text(json.dumps(_dns_row("www.example.com")) + "\n")
    assert canary_tokens.collect_dns_hits(tmp_path, store)["appended"] == 0
    assert token["fqdn"] not in store.read_text()


def test_dns_ignores_its_own_derived_rows(tmp_path):
    token = canary_tokens.create(tmp_path, "dns", domain="assets.internal")
    store = _store(tmp_path)
    store.write_text(json.dumps({
        "ts": "2026-11-19T10:00:00Z", "host": "WS1", "source": "canary",
        "kind": "alert", "event_id": 9001, "severity": "high",
        "score": 0.8, "dns_query": token["fqdn"],
    }) + "\n")
    assert canary_tokens.collect_dns_hits(tmp_path, store)["appended"] == 0


# ---------------------------------------------------------------------------
# HTTP collector
# ---------------------------------------------------------------------------

def test_http_collector_records_and_ingests(tmp_path):
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088")
    server, info = canary_tokens.make_server(
        tmp_path, "127.0.0.1", 0, max_requests=1)
    assert server is not None, info
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{info['port']}/t/{token['id']}"
        with urllib.request.urlopen(url, timeout=5) as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "image/gif"
    finally:
        thread.join(timeout=5)
        server.server_close()
    assert not thread.is_alive()
    hits = canary_tokens.last_hit(tmp_path)
    assert hits and hits["token_id"] == token["id"]

    store = _store(tmp_path)
    result = canary_tokens.collect_http_hits(tmp_path, store)
    assert result["appended"] == 1
    rows = [json.loads(line) for line in store.read_text().splitlines()]
    assert rows[-1]["source"] == "canary"
    assert rows[-1]["alert_id"] == f"canary:http:{token['id']}"
    assert canary_tokens.collect_http_hits(tmp_path, store)["appended"] == 0


def test_http_growth_does_not_reingest_the_first_hit(tmp_path):
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088")
    store = _store(tmp_path)
    canary_tokens.record_http_hit(tmp_path, token["id"], "127.0.0.1", "first")
    first = canary_tokens.collect_http_hits(tmp_path, store)
    assert first["appended"] == 1
    canary_tokens.record_http_hit(tmp_path, token["id"], "127.0.0.1", "second")
    second = canary_tokens.collect_http_hits(tmp_path, store)
    assert second["appended"] == 1, "the first hit was re-ingested"
    third = canary_tokens.collect_http_hits(tmp_path, store)
    assert third["appended"] == 0


def test_http_collector_rejects_unknown_token(tmp_path):
    canary_tokens.create(tmp_path, "http", base_url="http://collector:8088")
    server, info = canary_tokens.make_server(tmp_path, "127.0.0.1", 0)
    assert server is not None, info
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(
                f"http://127.0.0.1:{info['port']}/t/{'deadbeef' * 3}",
                timeout=5)
        assert exc.value.code == 404
        exc.value.close()
        with pytest.raises(urllib.error.HTTPError) as exc2:
            urllib.request.urlopen(
                f"http://127.0.0.1:{info['port']}/not-a-token", timeout=5)
        exc2.value.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_head_fingerprint_tracks_consumed_prefix_not_whole_file(tmp_path):
    path = tmp_path / "small.log"
    path.write_bytes(b"x" * 100)
    assert watch._head_token(path, 0) == ""
    first = watch._head_token(path, 100)
    path.write_bytes(b"x" * 100 + b"y" * 100)
    assert watch._head_token(path, 100) == first
    assert len(first) == 40


def test_http_collector_refuses_non_loopback_without_flag(tmp_path):
    server, info = canary_tokens.make_server(tmp_path, "0.0.0.0", 0)
    assert server is None
    assert "non-loopback" in info["error"]


def test_http_collector_get_only(tmp_path):
    token = canary_tokens.create(
        tmp_path, "http", base_url="http://collector:8088")
    server, info = canary_tokens.make_server(tmp_path, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{info['port']}/t/{token['id']}",
            data=b"x", method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 405
        exc.value.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


# ---------------------------------------------------------------------------
# watch integration
# ---------------------------------------------------------------------------

def test_watch_sweep_surfaces_dns_http_and_account_without_duplicates(
        tmp_path, monkeypatch):
    token = canary_tokens.create(tmp_path, "dns", domain="assets.internal")
    store = _store(tmp_path)
    store.write_text(json.dumps(_dns_row(token["fqdn"])) + "\n")
    (tmp_path / "config.json").write_text(json.dumps({
        "events_path": str(store),
        "canary": {"accounts": ["svc-print-archive"]},
    }))
    canary_tokens.record_http_hit(
        tmp_path, canary_tokens.create(
            tmp_path, "http", base_url="http://collector:8088")["id"],
        "203.0.113.9", "test-agent")
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: (
                            {"question": q, "blind_count": 0}
                            if q != "canary" else
                            {"question": "canary", "hit_count": 1, "hits": [{
                                "when": "2026-11-19T10:00:00Z", "id": 4624,
                                "user": "svc-print-archive",
                                "source_ip": "203.0.113.10",
                                "logon_type": 3,
                            }]}))
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    first = watch.sweep(tmp_path)
    types = [f["type"] for f in first["findings"]]
    assert "canary_dns_tripped" in types
    assert "canary_http_tripped" in types
    assert "canary_account_tripped" in types
    second = watch.sweep(tmp_path)
    assert not [f for f in second["findings"]
                if f["type"].startswith("canary_")]


def test_canary_dns_enforcement_is_approval_gated():
    policy = dict(enforce.DEFAULT_POLICY)
    policy["min_score"] = 8
    proposals = enforce.proposals([{
        "type": "canary_dns_tripped", "score": 8,
        "detail": "canary DNS token queried",
    }], policy)
    assert proposals
    assert proposals[0]["action"] == "isolate_host"
    assert proposals[0]["mode"] == "pending_approval"
