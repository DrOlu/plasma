"""Hash-chained provenance ledger.

Every agent decision and action is appended here before the result is
returned to the harness. The chain makes tampering visible and gives an
auditor the answer to "why did the agent do that?" — model/harness
version, prompt hash, arguments, policy digest, approval and outcome.
"""

from __future__ import annotations

import calendar
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

from . import agentstate

LEDGER_DIR = "ledger"
LEDGER_FILE = "ledger.jsonl"
GENESIS = "0" * 64


class LedgerError(RuntimeError):
    pass


def ledger_path(root=None) -> Path:
    return agentstate.base(root) / LEDGER_DIR / LEDGER_FILE


@contextmanager
def _lock(root=None):
    directory = agentstate.ensure(root) / LEDGER_DIR
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / ".lock"
    deadline = time.time() + 10
    fd = None
    while fd is None:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink()
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise LedgerError("ledger is locked by another writer")
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(fd)
        try:
            lock.unlink()
        except OSError:
            pass


def read(root=None) -> list[dict]:
    path = ledger_path(root)
    if not path.exists():
        return []
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"ledger line {number} is not JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise LedgerError(f"ledger line {number} is not an object")
        rows.append(row)
    return rows


def _row_hash(row: dict) -> str:
    payload = {k: v for k, v in row.items() if k != "hash"}
    return agentstate.sha256_obj(payload)


def append(root=None, entry: dict | None = None, tenant: str = "default") -> dict:
    entry = dict(entry or {})
    with _lock(root):
        rows = read(root)
        seq = (rows[-1].get("seq", 0) + 1) if rows else 1
        prev = rows[-1].get("hash", GENESIS) if rows else GENESIS
        row = {
            "seq": seq,
            "ts": entry.pop("ts", None) or agentstate.now_iso(),
            "tenant": entry.pop("tenant", tenant) or tenant,
            "kind": entry.pop("kind", "action"),
            "agent": entry.pop("agent", None),
            "model": entry.pop("model", None),
            "prompt_sha256": entry.pop("prompt_sha256", None),
            "tool": entry.pop("tool", None),
            "args": entry.pop("args", None),
            "args_sha256": entry.pop("args_sha256", None),
            "risk": entry.pop("risk", None),
            "decision": entry.pop("decision", None),
            "reasons": entry.pop("reasons", []),
            "policy_sha256": entry.pop("policy_sha256", None),
            "approval_id": entry.pop("approval_id", None),
            "outcome": entry.pop("outcome", None),
            "detail": entry.pop("detail", None),
            "prev": prev,
        }
        row.update(entry)
        row["hash"] = _row_hash(row)
        path = ledger_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return row


def record(root=None, *, tool: str, args: dict, decision: dict,
           context: dict | None = None, outcome: str | None = None,
           approval_id: int | None = None, detail=None, tenant: str = "default") -> dict:
    context = context or {}
    return append(root, {
        "kind": "action",
        "tenant": context.get("tenant", tenant),
        "agent": context.get("agent"),
        "model": context.get("model"),
        "prompt_sha256": context.get("prompt_sha256"),
        "tool": tool,
        "args": args,
        "args_sha256": agentstate.sha256_obj({"tool": tool, "args": args}),
        "risk": decision.get("risk"),
        "decision": decision.get("code"),
        "reasons": decision.get("reasons", []),
        "policy_sha256": decision.get("policy_sha256"),
        "approval_id": approval_id,
        "outcome": outcome,
        "detail": detail,
    })


def verify(root=None) -> dict:
    try:
        rows = read(root)
    except LedgerError as exc:
        return {"ok": False, "rows": 0, "broken": None, "reason": str(exc)}
    prev = GENESIS
    for index, row in enumerate(rows, 1):
        if row.get("seq") != index:
            return {"ok": False, "rows": len(rows), "broken": index,
                    "reason": "sequence gap"}
        if row.get("prev") != prev:
            return {"ok": False, "rows": len(rows), "broken": index,
                    "reason": "previous hash mismatch"}
        if row.get("hash") != _row_hash(row):
            return {"ok": False, "rows": len(rows), "broken": index,
                    "reason": "row hash mismatch"}
        prev = row["hash"]
    return {"ok": True, "rows": len(rows), "broken": None, "reason": None}


def tail(root=None, limit: int = 20) -> list[dict]:
    rows = read(root)
    return rows[-max(1, int(limit)):]


def find(root=None, seq: int | None = None) -> dict | None:
    if seq is None:
        return None
    for row in read(root):
        if row.get("seq") == seq:
            return row
    return None


def count_recent(root=None, seconds: int = 60, tool: str | None = None) -> int:
    cutoff = time.time() - max(1, int(seconds))
    count = 0
    for row in read(root):
        if row.get("kind") != "action":
            continue
        if tool and row.get("tool") != tool:
            continue
        ts = row.get("ts", "")
        try:
            stamp = calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
        except (ValueError, TypeError):
            continue
        if stamp >= cutoff:
            count += 1
    return count


def pending_approvals(root=None, limit: int = 200) -> list[dict]:
    rows = read(root)
    approved = {r.get("approval_for") for r in rows
                if r.get("kind") == "approval" and r.get("approved")}
    consumed = {r.get("approval_id") for r in rows
                if r.get("kind") == "action" and r.get("approval_id") is not None}
    out = []
    for row in rows:
        if row.get("kind") != "action" or row.get("decision") != "approval_required":
            continue
        seq = row.get("seq")
        if seq in approved or seq in consumed:
            continue
        out.append(row)
    return out[-max(1, int(limit)):]


def approve(root, seq: int, approver: str, note: str = "",
            approve_action: bool = True, tenant: str = "default") -> dict:
    target = find(root, seq)
    if target is None:
        raise LedgerError(f"no ledger row {seq}")
    if target.get("kind") != "action" or target.get("decision") != "approval_required":
        raise LedgerError(f"row {seq} is not a pending approval")
    return append(root, {
        "kind": "approval",
        "tenant": target.get("tenant", tenant),
        "approval_for": seq,
        "approved": bool(approve_action),
        "approver": approver,
        "note": note,
        "tool": target.get("tool"),
        "args_sha256": target.get("args_sha256"),
    })


def find_approval(root=None, seq: int | None = None, tool: str | None = None,
                  args_sha256: str | None = None) -> dict | None:
    if seq is None:
        return None
    rows = read(root)
    consumed = {r.get("approval_id") for r in rows
                if r.get("kind") == "action" and r.get("approval_id") is not None}
    for row in rows:
        if (row.get("kind") == "approval" and row.get("approval_for") == seq
                and row.get("approved") is True
                and row.get("tool") == tool
                and row.get("args_sha256") == args_sha256
                and seq not in consumed):
            return row
    return None