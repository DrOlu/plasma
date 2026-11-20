# ruff: noqa: ISC004
"""Local case workspace: durable, portable investigation artifacts.

An agent can query the event store in one turn, but an investigation that
matters needs to survive the turn. A case is a directory under
``<root>/cases/<name>`` containing the selected events, findings, operator
notes, a rendered report and a sealed manifest.

Nothing here is a service. Cases are plain files, easy to copy into a
ticket, archive or evidence bundle. ``seal`` hashes every artifact and
``verify`` detects later changes.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path

from . import agentstate
from . import query as query_mod

CASE_SCHEMA = "plasma.case/1"
CASE_ROOT = "cases"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class CaseError(ValueError):
    """Invalid case name, path or artifact."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _name(name: str) -> str:
    raw = str(name or "").strip()
    if "/" in raw or "\\" in raw or ".." in raw:
        raise CaseError("case name must not contain a path separator or '..'")
    text = _SAFE.sub("-", raw).strip(".-")
    if not text or len(text) > 120:
        raise CaseError("case name must be 1-120 letters, digits, '.', '_' or '-'")
    return text


def case_dir(root, name: str) -> Path:
    return Path(root) / CASE_ROOT / _name(name)


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True,
                              default=str) + "\n", encoding="utf-8")
    tmp.replace(path)


def _append_jsonl(path: Path, rows) -> int:
    rows = [row for row in rows if isinstance(row, dict)]
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _jsonl(path)
    seen = {agentstate.sha256_obj(row) for row in existing}
    written = 0
    agentstate.ensure_trailing_newline(path)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            digest = agentstate.sha256_obj(row)
            if digest in seen:
                continue
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            seen.add(digest)
            written += 1
    return written


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    except OSError:
        return []
    return rows


def _meta(root, name: str) -> dict:
    directory = case_dir(root, name)
    path = directory / "case.json"
    if not path.exists():
        raise CaseError(f"case {name!r} does not exist")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseError(f"case {name!r} has an unreadable case.json") from exc
    return data


def _save_meta(root, name: str, meta: dict) -> None:
    _write_json(case_dir(root, name) / "case.json", meta)


def open_case(root, name: str, host: str | None = None,
              note: str | None = None, title: str | None = None) -> dict:
    """Create or reopen a case. Reopening never clears evidence."""
    safe = _name(name)
    directory = case_dir(root, safe)
    path = directory / "case.json"
    if path.exists():
        meta = _meta(root, safe)
        meta["reopened"] = _now()
        if title:
            meta["title"] = str(title)[:200]
        _save_meta(root, safe, meta)
        if note:
            add_note(root, safe, note)
        return {"ok": True, "created": False, "case": _meta(root, safe),
                "dir": str(directory)}
    directory.mkdir(parents=True, exist_ok=True)
    meta = {
        "schema": CASE_SCHEMA,
        "name": safe,
        "title": str(title or safe)[:200],
        "host": host,
        "created": _now(),
        "status": "open",
        "counts": {"events": 0, "findings": 0, "notes": 0},
    }
    _save_meta(root, safe, meta)
    for filename in ("events.jsonl", "findings.jsonl", "notes.md"):
        (directory / filename).touch()
    if note:
        add_note(root, safe, note)
    return {"ok": True, "created": True, "case": meta,
            "dir": str(directory)}


def list_cases(root) -> dict:
    base = Path(root) / CASE_ROOT
    rows = []
    if base.is_dir():
        for path in sorted(base.glob("*/case.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                rows.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
    return {"count": len(rows), "cases": rows[:100]}


def _update_counts(root, name: str, meta: dict) -> dict:
    directory = case_dir(root, name)
    meta["counts"] = {
        "events": len(_jsonl(directory / "events.jsonl")),
        "findings": len(_jsonl(directory / "findings.jsonl")),
        "notes": _note_count(directory / "notes.md"),
    }
    meta["updated"] = _now()
    _save_meta(root, name, meta)
    return meta


def add_events(root, name: str, rows) -> dict:
    meta = _meta(root, name)
    written = _append_jsonl(case_dir(root, name) / "events.jsonl", rows)
    meta = _update_counts(root, name, meta)
    return {"ok": True, "case": name, "added": written,
            "counts": meta["counts"]}


def add_findings(root, name: str, rows) -> dict:
    meta = _meta(root, name)
    written = _append_jsonl(case_dir(root, name) / "findings.jsonl", rows)
    meta = _update_counts(root, name, meta)
    return {"ok": True, "case": name, "added": written,
            "counts": meta["counts"]}


def add_query(root, name: str, spec: dict | None = None,
              events_path=None) -> dict:
    """Run a typed query and copy its matching rows into the case."""
    result = query_mod.query(
        events_path or Path(root) / "data" / "events.jsonl", spec or {},
        max_rows=int((spec or {}).get("max_rows", query_mod.DEFAULT_MAX_ROWS)))
    added = add_events(root, name, result.get("events") or [])
    return {"ok": True, "case": name, "query": result.get("query"),
            "matched": result.get("matched"),
            "returned": result.get("returned"),
            "truncated": result.get("truncated"), **added}


def add_note(root, name: str, text: str) -> dict:
    meta = _meta(root, name)
    text = str(text or "").strip()
    if not text:
        raise CaseError("note text is empty")
    path = case_dir(root, name) / "notes.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    agentstate.ensure_trailing_newline(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"- {_now()} — {text[:4000]}\n")
    meta = _update_counts(root, name, meta)
    return {"ok": True, "case": name, "notes": meta["counts"]["notes"]}


def _note_count(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(
            encoding="utf-8", errors="replace").splitlines()
            if line.startswith("- "))
    except OSError:
        return 0


def _notes(path: Path) -> list[dict]:
    rows = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in text.splitlines():
        if not line.startswith("- "):
            continue
        body = line[2:]
        ts, sep, note = body.partition(" — ")
        rows.append({"ts": ts if sep else None,
                     "kind": "note", "source": "operator",
                     "description": note if sep else body})
    return rows


def timeline(root, name: str) -> dict:
    meta = _meta(root, name)
    directory = case_dir(root, name)
    rows = []
    for row in _jsonl(directory / "events.jsonl"):
        rows.append({
            "ts": row.get("ts"), "kind": row.get("kind"),
            "source": row.get("source"), "host": row.get("host"),
            "user": row.get("user"), "process": row.get("process"),
            "pid": row.get("pid"), "score": row.get("score"),
            "description": row.get("description"),
        })
    for row in _jsonl(directory / "findings.jsonl"):
        rows.append({
            "ts": row.get("ts") or row.get("detected_at"),
            "kind": "finding", "source": row.get("source") or "plasma",
            "host": row.get("host"), "user": row.get("user"),
            "process": row.get("process"), "pid": row.get("pid"),
            "score": row.get("score"),
            "description": row.get("description") or row.get("title"),
        })
    rows.extend(_notes(directory / "notes.md"))
    rows.sort(key=lambda r: str(r.get("ts") or ""))
    return {"ok": True, "case": meta.get("name"), "count": len(rows),
            "timeline": rows[:2000], "truncated": len(rows) > 2000}


def _score_counts(rows) -> list[dict]:
    buckets = Counter()
    for row in rows:
        try:
            score = float(row.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        if score >= 0.9:
            buckets["critical"] += 1
        elif score >= 0.7:
            buckets["high"] += 1
        elif score >= 0.4:
            buckets["medium"] += 1
        else:
            buckets["low"] += 1
    return [{"band": key, "count": buckets[key]}
            for key in ("critical", "high", "medium", "low") if buckets[key]]


def report(root, name: str, write: bool = True) -> dict:
    meta = _meta(root, name)
    directory = case_dir(root, name)
    events = _jsonl(directory / "events.jsonl")
    findings = _jsonl(directory / "findings.jsonl")
    notes = _notes(directory / "notes.md")
    by_kind = Counter(str(r.get("kind") or "unknown") for r in events)
    by_source = Counter(str(r.get("source") or "unknown") for r in events)
    scores = _score_counts(events + findings)
    high = sorted(
        [r for r in events + findings
         if isinstance(r.get("score"), (int, float)) and float(r["score"]) >= 0.7],
        key=lambda r: float(r.get("score") or 0), reverse=True)[:15]
    lines = [
        f"# Case {meta.get('name')}",
        "",
        f"- **Title:** {meta.get('title') or meta.get('name')}",
        f"- **Host:** {meta.get('host') or 'not specified'}",
        f"- **Created:** {meta.get('created')}",
        f"- **Status:** {meta.get('status') or 'open'}",
        f"- **Events:** {len(events)}  **Findings:** {len(findings)}  "
        f"**Notes:** {len(notes)}",
        "",
        "## Detection summary",
        "",
    ]
    if scores:
        lines.append("| Band | Count |")
        lines.append("|---|---:|")
        for row in scores:
            lines.append(f"| {row['band']} | {row['count']} |")
    else:
        lines.append("No scored rows.")
    lines += ["", "## Event kinds", ""]
    if by_kind:
        lines += ["| Kind | Count |", "|---|---:|"]
        for key, count in by_kind.most_common():
            lines.append(f"| {key} | {count} |")
    else:
        lines.append("No events collected.")
    lines += ["", "## Sources", ""]
    for key, count in by_source.most_common():
        lines.append(f"- {key}: {count}")
    lines += ["", "## Highest-scoring rows", ""]
    if high:
        lines += ["| Score | Time | Kind | Process | Description |",
                  "|---:|---|---|---|---|"]
        for row in high:
            desc = str(row.get("description") or "").replace("|", "\\|")[:180]
            lines.append(
                f"| {float(row.get('score') or 0):.2f} | {row.get('ts')} | "
                f"{row.get('kind') or ''} | {row.get('process') or ''} | {desc} |")
    else:
        lines.append("None at or above 0.7.")
    lines += ["", "## Operator notes", ""]
    lines += [f"- {note.get('ts') or ''} — {note.get('description')}"
              for note in notes] or ["None."]
    markdown = "\n".join(lines).rstrip() + "\n"
    path = directory / "report.md"
    if write:
        path.write_text(markdown, encoding="utf-8")
        _update_counts(root, name, meta)
    return {"ok": True, "case": meta.get("name"),
            "path": str(path) if write else None,
            "markdown": markdown, "summary": {
                "events": len(events), "findings": len(findings),
                "notes": len(notes), "scores": scores,
                "kinds": dict(by_kind), "sources": dict(by_source),
            }}


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def seal(root, name: str) -> dict:
    """Hash every case artifact and write a tamper-evident manifest."""
    meta = _meta(root, name)
    directory = case_dir(root, name)
    report_path = directory / "report.md"
    if not report_path.exists():
        report(root, name)
        meta = _meta(root, name)
    # Record the sealed status BEFORE hashing: case.json is itself an
    # artifact, and rewriting it after the manifest would self-tamper.
    meta["status"] = "sealed"
    meta["sealed_at"] = _now()
    _save_meta(root, name, meta)
    files = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        files[path.name] = {"sha256": _digest(path), "bytes": path.stat().st_size}
    chain = hashlib.sha256()
    for filename in sorted(files):
        chain.update(f"{filename}:{files[filename]['sha256']}\n".encode())
    manifest = {
        "schema": CASE_SCHEMA,
        "case": meta.get("name"),
        "sealed_at": _now(),
        "files": files,
        "chain_sha256": chain.hexdigest(),
    }
    _write_json(directory / "manifest.json", manifest)
    return {"ok": True, "case": meta.get("name"),
            "manifest": str(directory / "manifest.json"), **manifest}


def verify(root, name: str) -> dict:
    """Recompute the sealed manifest. Any changed/missing artifact is a fail."""
    meta = _meta(root, name)
    directory = case_dir(root, name)
    path = directory / "manifest.json"
    if not path.exists():
        return {"ok": False, "case": meta.get("name"), "code": "NOT_SEALED",
                "error": "case has no manifest; run plasma case seal first"}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "case": meta.get("name"), "code": "BAD_MANIFEST",
                "error": str(exc)[:300]}
    changed, missing = [], []
    for filename, expected in (manifest.get("files") or {}).items():
        artifact = directory / filename
        if not artifact.exists():
            missing.append(filename)
        elif _digest(artifact) != expected.get("sha256"):
            changed.append(filename)
    chain = hashlib.sha256()
    for filename in sorted(manifest.get("files") or {}):
        chain.update(
            f"{filename}:{manifest['files'][filename]['sha256']}\n".encode())
    chain_ok = chain.hexdigest() == manifest.get("chain_sha256")
    ok = not changed and not missing and chain_ok
    return {"ok": ok, "case": meta.get("name"),
            "changed": changed, "missing": missing, "chain_ok": chain_ok,
            "sealed_at": manifest.get("sealed_at"),
            "checked": len(manifest.get("files") or {}),
            "code": "VERIFIED" if ok else "TAMPERED"}
