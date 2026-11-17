"""HTTP API tests for `plasma serve`.

The server is started on an ephemeral loopback port and driven over real
HTTP. Each test is independent; the fixture shuts the server down.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from plasma import serve


def _start(tmp_path, **kwargs):
    params = {"root": tmp_path, "host": "127.0.0.1", "port": 0,
              "api_key": "testkey", "quiet": True}
    params.update(kwargs)
    server, key = serve.make_server(**params)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return server, key, base


@pytest.fixture
def running(tmp_path):
    server, key, base = _start(tmp_path)
    try:
        yield server, key, base
    finally:
        server.shutdown()
        server.server_close()


def _request(base, path, method="GET", payload=None, key=None, headers=None):
    data = None
    hdrs = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if key:
        hdrs["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base + path, data=data, headers=hdrs,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# routing and auth
# ---------------------------------------------------------------------------

def test_healthz_is_unauthenticated(running):
    _, _, base = running
    status, body = _request(base, "/healthz")
    assert status == 200
    assert body["ok"] is True and body["product"] == "Plasma"


def test_version_requires_key(running):
    _, _, base = running
    status, body = _request(base, "/v1/version")
    assert status == 401
    assert body["code"] == "unauthorized"


def test_bearer_key_accepted(running):
    _, key, base = running
    status, body = _request(base, "/v1/version", key=key)
    assert status == 200
    assert body["ok"] is True


def test_x_api_key_header_accepted(running):
    _, key, base = running
    status, body = _request(base, "/v1/version", headers={"X-API-Key": key})
    assert status == 200 and body["ok"] is True


def test_query_string_key_is_not_accepted(running):
    _, key, base = running
    status, _ = _request(base, f"/v1/version?api_key={key}")
    assert status == 401


def test_unknown_route(running):
    _, key, base = running
    status, body = _request(base, "/v1/nope", key=key)
    assert status == 404 and body["code"] == "not_found"


def test_method_not_allowed(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="PUT", key=key)
    assert status == 405 and body["code"] == "method"


# ---------------------------------------------------------------------------
# introspection
# ---------------------------------------------------------------------------

def test_commands_mirror_the_cli(running):
    _, key, base = running
    status, body = _request(base, "/v1/commands", key=key)
    assert status == 200
    paths = {tuple(row["path"]) for row in body["commands"]}
    assert ("health",) in paths
    assert ("actuate", "actions") in paths
    assert ("control", "policy", "set") in paths
    assert ("serve",) in paths


def test_commands_mark_mutating_and_long_running(running):
    _, key, base = running
    _, body = _request(base, "/v1/commands", key=key)
    by_path = {tuple(row["path"]): row for row in body["commands"]}
    assert by_path[("control", "policy", "set")]["mutating"] is True
    assert by_path[("actuate", "actions")]["mutating"] is False
    assert by_path[("serve",)]["long_running"] is True


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------

def test_exec_runs_a_read_only_command(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["actuate", "actions"]})
    assert status == 200
    assert body["ok"] is True and body["exit_code"] == 0
    assert body["command"] == "actuate actions"
    assert body["result"] is not None


def test_exec_command_and_args_alias(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST", key=key,
                           payload={"command": "actuate", "args": ["actions"]})
    assert status == 200 and body["ok"] is True


def test_exec_version(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["--version"]})
    assert status == 200 and body["exit_code"] == 0
    assert "plasma" in body["stdout"].lower()


def test_exec_help(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["--help"]})
    assert status == 200 and body["exit_code"] == 0
    assert "usage" in body["stdout"].lower()


def test_exec_unknown_command_is_rejected(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["bogus"]})
    assert status == 400 and body["code"] == "argv"


def test_exec_missing_required_argument_is_rejected(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["actuate", "apply"]})
    assert status == 400 and body["code"] == "argv"


def test_exec_long_running_is_rejected(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": ["watch", "loop"]})
    assert status == 400 and body["code"] == "long_running"


def test_exec_rejects_bad_argv_types(running):
    _, key, base = running
    status, body = _request(base, "/v1/exec", method="POST",
                           key=key, payload={"argv": "health"})
    assert status == 400 and body["code"] == "argv"


# ---------------------------------------------------------------------------
# read-only mode
# ---------------------------------------------------------------------------

def test_read_only_allows_reads(tmp_path):
    server, key, base = _start(tmp_path, read_only=True)
    try:
        status, body = _request(base, "/v1/exec", method="POST", key=key,
                               payload={"argv": ["actuate", "actions"]})
        assert status == 200 and body["ok"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_read_only_denies_apply(tmp_path):
    server, key, base = _start(tmp_path, read_only=True)
    try:
        status, body = _request(base, "/v1/exec", method="POST", key=key,
                               payload={"argv": [
                                   "actuate", "apply", "block_ip",
                                   "--target", "192.0.2.1",
                                   "--reason", "test", "--apply"]})
        assert status == 403 and body["code"] == "read_only"
    finally:
        server.shutdown()
        server.server_close()


def test_read_only_denies_policy_set(tmp_path):
    server, key, base = _start(tmp_path, read_only=True)
    try:
        status, body = _request(base, "/v1/exec", method="POST", key=key,
                               payload={"argv": ["control", "policy", "set",
                                                 "--autonomy", "autonomous"]})
        assert status == 403 and body["code"] == "read_only"
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# body limits and audit
# ---------------------------------------------------------------------------

def test_body_too_large(tmp_path):
    server, key, base = _start(tmp_path, max_body=16)
    try:
        status, body = _request(base, "/v1/exec", method="POST", key=key,
                               payload={"argv": ["actuate", "actions"]})
        assert status == 413 and body["code"] == "body"
    finally:
        server.shutdown()
        server.server_close()


def test_audit_row_is_written(tmp_path):
    server, key, base = _start(tmp_path)
    try:
        _request(base, "/v1/exec", method="POST", key=key,
                 payload={"argv": ["actuate", "actions"]})
        path = tmp_path / "serve" / "audit.jsonl"
        assert path.exists()
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        assert rows and rows[-1]["command"] == "actuate actions"
        assert rows[-1]["outcome"] == "ok"
        assert "testkey" not in path.read_text()
    finally:
        server.shutdown()
        server.server_close()


def test_audit_can_be_disabled(tmp_path):
    server, key, base = _start(tmp_path, audit=False)
    try:
        _request(base, "/v1/exec", method="POST", key=key,
                 payload={"argv": ["actuate", "actions"]})
        assert not (tmp_path / "serve" / "audit.jsonl").exists()
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# key resolution and unit helpers
# ---------------------------------------------------------------------------

def test_default_key(tmp_path, monkeypatch):
    monkeypatch.delenv("PLASMA_SERVE_API_KEY", raising=False)
    assert serve.resolve_api_key() == "plasmaplasma"


def test_env_key_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("PLASMA_SERVE_API_KEY", "env-key")
    assert serve.resolve_api_key() == "env-key"


def test_key_file(tmp_path, monkeypatch):
    monkeypatch.delenv("PLASMA_SERVE_API_KEY", raising=False)
    key_file = tmp_path / "key.txt"
    key_file.write_text("\nfrom-file\n")
    assert serve.resolve_api_key(api_key_file=str(key_file)) == "from-file"


def test_empty_key_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("PLASMA_SERVE_API_KEY", raising=False)
    key_file = tmp_path / "empty.txt"
    key_file.write_text("\n\n")
    with pytest.raises(serve.ServeError):
        serve.resolve_api_key(api_key_file=str(key_file))


def test_tls_needs_both_cert_and_key(tmp_path):
    with pytest.raises(serve.ServeError):
        serve.make_server(root=tmp_path, tls_cert="cert.pem")


def test_command_path_and_mutation_rules():
    assert serve.command_path(["control", "policy", "set", "--autonomy", "x"]) == \
        "control policy set"
    assert serve.command_path(["actuate", "apply", "block_ip"]) == \
        "actuate apply block_ip"
    assert serve.is_mutating(["actuate", "apply", "block_ip"]) is True
    assert serve.is_mutating(["actuate", "actions"]) is False
    assert serve.is_mutating(["health", "--apply"]) is True
    assert serve.is_long_running("watch loop") is True
    assert serve.is_long_running("watch once") is False
