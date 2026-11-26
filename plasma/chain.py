"""Plasma chain: deterministic story-level detection over the events store.

Single findings say "this happened". Chains say "this happened, then this,
then this — that is a story". A chain is an ordered sequence of step
matchers over normalized PlasmaEvent rows; every adjacent pair must fall
within the chain's gap window. No ML, no scores learned from data — a
written suspicion story, exactly like a gene rule but across time.

Chains scan the LAST `max_rows` rows of the events store (oldest→newest),
so findings are always about recent history.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .fleet import _parse_ts

DEFAULT_WINDOW = 1800        # max seconds between adjacent chain steps
DEFAULT_MAX_ROWS = 5000      # scan tail size, bounded like every probe

# step matcher fields:
#   any of: kind, process (regex on basename-ish field), user (regex),
#           event_id, description (regex), dest_ip present?;
#           exclude_parent (regex) drops events spawned by a matching parent.
# each built-in chain: name, score, gap_seconds, steps in time order;
# bind_user / bind_process require every step to share one identity or image.

BUILTIN_CHAINS = [
    {
        "name": "phish_spawn_chain",
        "score": 9,
        "gap_seconds": 900,
        "detail": "office app spawned a script host, then an encoded/obfuscated "
                  "command or egress followed",
        "steps": [
            {"kind": "process", "process": r"(?i)(winword|excel|powerpnt|outlook)\.exe$"},
            {"kind": "process", "process": r"(?i)(powershell|wscript|cscript|mshta)\.exe$"},
            {"any_of": [
                {"description": r"(?i)(-enc|-ec|encodedcommand|frombase64|downloadstring|webclient)"},
                {"kind": "network"},
            ]},
        ],
    },
    {
        "name": "brute_force_success",
        "score": 8,
        "gap_seconds": 3600,
        "min_failures": 4,
        "bind_user": True,
        "detail": "repeated failed logons against one user, then a success for that same user",
        "steps": [
            {"kind": "auth", "event_id": 4625, "user": r".+", "min_count": 4},
            {"kind": "auth", "event_id": 4624, "user": r".+"},
        ],
    },
    {
        "name": "kerberos_brute_force",
        "score": 9,
        "gap_seconds": 1800,
        "min_failures": 4,
        "bind_user": True,
        "detail": "repeated Kerberos pre-auth failures for one account, then a "
                  "TGT success for that same account (password spray)",
        "steps": [
            {"kind": "auth", "event_id": 4771, "user": r".+", "min_count": 4},
            {"kind": "auth", "event_id": 4768, "user": r".+"},
        ],
    },
    {
        "name": "persistence_after_privilege",
        "score": 9,
        "gap_seconds": 3600,
        "detail": "account/admin change followed by a persistence-shaped alert",
        "steps": [
            {"any_of": [
                {"description": r"(?i)(net1? .*(user|localgroup).*(/add| add)|add-localgroupmember|new-localuser)"},
                {"kind": "auth", "event_id": 4732},
                {"kind": "auth", "event_id": 4728},
                {"kind": "auth", "event_id": 4756},
            ]},
            {"description": r"(?i)(schtasks(?:\.exe)?[^|]*?/create|new-service|register-scheduledtask|sc(?:\.exe)?\s+create|reg(?:\.exe)?\s+add[^\n]*\\run|new-itemproperty[^\n]*\\run|set-itemproperty[^\n]*\\run|win32_scheduledjob|new-scheduledtask(?:trigger)?)",
             "exclude_parent": r"(?i)^plasma[^\\]*\.exe$",
             # WHIDS downgrades benign installer/servicing rows to 0.2; a
             # chain story must not be completed by one of those.
             "min_score": 0.2},
        ],
    },
    {
        "name": "account_creation_privilege",
        "score": 9,
        "gap_seconds": 1800,
        "detail": "a new account was created, then added to a privileged group",
        "steps": [
            {"kind": "auth", "event_id": 4720},
            {"mentions_prev_user": True,
             "any_of": [
                 {"kind": "auth", "event_id": 4728},
                 {"kind": "auth", "event_id": 4732},
                 {"kind": "auth", "event_id": 4756},
             ]},
        ],
    },
    {
        "name": "injection_chain",
        "score": 9,
        "gap_seconds": 120,
        "bind_process": True,
        "detail": "cross-process RWX permission flip followed by thread creation "
                  "in another process by the same image",
        "steps": [
            {"kind": "trace",
             "description": r'(?i)dtrace inject-rwx.*"self":\s*0'},
            {"kind": "trace", "description": r"(?i)dtrace inject-remote-thread"},
        ],
    },
    {
        "name": "injection_hollow_chain",
        "score": 9,
        "gap_seconds": 120,
        "bind_process": True,
        "detail": "remote image unmap, remote write, then thread creation by "
                  "the same image (process hollowing)",
        "steps": [
            {"kind": "trace", "description": r"(?i)dtrace inject-hollow"},
            {"kind": "trace", "description": r"(?i)dtrace inject-write"},
            {"kind": "trace", "description": r"(?i)dtrace inject-remote-thread"},
        ],
    },
    {
        "name": "injection_section_chain",
        "score": 9,
        "gap_seconds": 60,
        "bind_process": True,
        "detail": "remote section map followed by thread creation by the same "
                  "image",
        "steps": [
            {"kind": "trace", "description": r"(?i)dtrace inject-section"},
            {"kind": "trace", "description": r"(?i)dtrace inject-remote-thread"},
        ],
    },
    {
        "name": "injection_write_chain",
        "score": 9,
        "gap_seconds": 60,
        "bind_process": True,
        "detail": "remote memory write followed by thread creation by the same "
                  "image (no RWX flip required)",
        "steps": [
            {"kind": "trace", "description": r"(?i)dtrace inject-write"},
            {"kind": "trace", "description": r"(?i)dtrace inject-remote-thread"},
        ],
    },
    {
        "name": "injection_hijack_chain",
        "score": 8,
        "gap_seconds": 60,
        "bind_process": True,
        "detail": "thread context rewritten on another thread, then a remote "
                  "thread created by the same image",
        "steps": [
            {"kind": "trace", "description": r"(?i)dtrace inject-hijack"},
            {"kind": "trace", "description": r"(?i)dtrace inject-remote-thread"},
        ],
    },
    {
        "name": "injection_apc_chain",
        "score": 9,
        "gap_seconds": 30,
        "bind_process": True,
        "detail": "cross-process RWX permission flip followed by an APC queued "
                  "by the same image",
        "steps": [
            {"kind": "trace",
             "description": r'(?i)dtrace inject-rwx.*"self":\s*0'},
            {"kind": "trace", "description": r"(?i)dtrace inject-apc"},
        ],
    },
]


def _match_step(step: dict, row: dict) -> bool:
    """One step matcher against one event row."""
    if "any_of" in step:
        return any(_match_step(s, row) for s in step["any_of"])
    kind = step.get("kind")
    if kind and str(row.get("kind", "")).lower() != kind.lower():
        return False
    eid = step.get("event_id")
    if eid is not None:
        try:
            if int(row.get("event_id") or 0) != int(eid):
                return False
        except (TypeError, ValueError):
            return False
    excluded_parent = step.get("exclude_parent")
    if excluded_parent:
        # Match the parent's basename: Windows paths arrive both as bare
        # names and as full paths, and an anchored pattern against the full
        # path silently skipped the exclusion.
        parent = str(row.get("parent") or "")
        base = parent.replace("/", "\\").split("\\")[-1]
        try:
            if base and re.search(excluded_parent, base):
                return False
        except re.error:
            return False
    min_score = step.get("min_score")
    if min_score is not None:
        try:
            row_score = float(row.get("score"))
        except (TypeError, ValueError):
            row_score = None
        if row_score is not None and row_score <= float(min_score):
            return False
    for field in ("process", "user", "description"):
        if field in step:
            value = str(row.get(field) or "")
            if field == "description":
                # A process event's narrative is split across description and
                # cmdline. Match both so a real 4688 `net user /add` row is
                # not missed just because the command lives in cmdline.
                value = value + "\n" + str(row.get("cmdline") or "")
            try:
                if not re.search(step[field], value):
                    return False
            except re.error:
                return False
    return True


def _ts(row: dict):
    return _parse_ts(row.get("ts"))


def _count_back(events, i, step, gap, user_filter=None):
    """Matches of `step` within `gap` seconds ending at events[i] (inclusive)."""
    t = _ts(events[i])
    count = 0
    k = i
    while k >= 0:
        tk = _ts(events[k])
        if tk is None or (t - tk).total_seconds() > gap:
            break
        if _match_step(step, events[k]) and (
                user_filter is None or _user_key(events[k]) == user_filter):
            count += 1
        k -= 1
    return count


def _user_key(row):
    """Normalized identity for cross-step binding.

    The domain is kept: CORP\\olu and EVIL\\olu are different identities,
    and a brute force against one must not chain onto a success for the
    other just because the account name collides."""
    user = row.get("user")
    if not user:
        return None
    value = str(user).strip().lower()
    if not value or value.endswith("$") or value in ("system", "-"):
        return None
    return value


def _proc_key(row):
    """Normalized image name for cross-step binding (C:\\x\\loader.exe -> loader.exe)."""
    process = row.get("process")
    if not process:
        return None
    value = str(process).split("\\")[-1].strip().lower()
    return value or None


def _match_from(steps, events, start, gap, t_prev=None, bound_user=None,
                bound_process=None, enforce_bound=False,
                enforce_process=False, bound_host=None):
    """Ordered forward match of steps against events[start:], full
    backtracking on step candidates. Returns indices or None. Each adjacent
    pair must sit within `gap` seconds. When `enforce_bound` is set, every
    step must belong to the same normalized user as the first step. When
    `enforce_process` is set, every step must carry the same image name.
    Steps are always bound to one host: a story stitched from events on
    different machines is not a story (PID/user spaces do not join)."""
    if not steps:
        return []
    step = steps[0]
    for i in range(start, len(events)):
        row = events[i]
        if not _match_step(step, row):
            continue
        if enforce_bound:
            row_user = _user_key(row)
            if row_user is None:
                continue
            if bound_user is not None and row_user != bound_user:
                continue
        if enforce_process:
            row_process = _proc_key(row)
            if row_process is None:
                continue
            if bound_process is not None and row_process != bound_process:
                continue
        row_host = str(row.get("host") or "").strip().lower()
        if bound_host and row_host and row_host != bound_host:
            continue
        if step.get("mentions_prev_user") and bound_user:
            # Bind on the bare account name: the group-add narrative
            # carries the member as a DN or bare name, not DOMAIN\\user.
            mention = bound_user.split("\\")[-1]
            narrative = (str(row.get("description") or "") + "\n"
                         + str(row.get("cmdline") or ""))
            try:
                if not re.search(rf"\b{re.escape(mention)}\b", narrative,
                                 re.IGNORECASE):
                    continue
            except re.error:
                continue
        t = _ts(row)
        if t_prev is not None and (t - t_prev).total_seconds() > gap:
            break          # sorted input: every later candidate is later still
        # count prior matches for THIS candidate's user, not every user
        # who happened to fail inside the window
        if step.get("min_count") and _count_back(
                events, i, step, gap,
                user_filter=_user_key(row) if enforce_bound else None
        ) < step["min_count"]:
            continue
        user = bound_user if bound_user is not None else _user_key(row)
        process = bound_process if bound_process is not None else _proc_key(row)
        rest = _match_from(steps[1:], events, i + 1, gap, t_prev=t,
                           bound_user=user, bound_process=process,
                           enforce_bound=enforce_bound,
                           enforce_process=enforce_process,
                           bound_host=row_host or bound_host)
        if rest is not None:
            return [i] + rest
    return None


def scan(rows: list[dict], chains: list[dict] | None = None,
         gap_seconds: int = DEFAULT_WINDOW) -> list[dict]:
    """Find chain matches in time-ordered rows. Returns findings."""
    chains = chains or BUILTIN_CHAINS
    events = [r for r in rows if _ts(r) is not None]
    events.sort(key=_ts)
    findings: list[dict] = []
    for chain in chains:
        gap = int(chain.get("gap_seconds", gap_seconds))
        # A store can hold several independent stories for one chain (two
        # users sprayed in the same hour). Report each non-overlapping
        # story, bounded so one noisy chain cannot flood the diary.
        start = 0
        for _ in range(10):
            idxs = _match_from(chain["steps"], events, start, gap,
                               enforce_bound=bool(chain.get("bind_user")),
                               enforce_process=bool(chain.get("bind_process")))
            if not idxs:
                break
            start = idxs[-1] + 1
            matched = [events[i] for i in idxs]
            t0, t1 = _ts(matched[0]), _ts(matched[-1])
            span_min = int((t1 - t0).total_seconds() / 60)
            users = sorted({_user_key(m) for m in matched if _user_key(m)})
            findings.append({
                "type": f"chain_{chain['name']}",
                "score": chain["score"],
                "gap_seconds": gap,
                "span_minutes": span_min,
                "users": users,
                "steps": len(matched),
                "detail": (chain["detail"] + f" — {len(matched)} events over "
                           f"{span_min} min" +
                           (f", users: {', '.join(users)}" if users else "")),
                "events": [
                    {"ts": m.get("ts"), "kind": m.get("kind"),
                     "user": m.get("user"), "process": m.get("process"),
                     "pid": m.get("pid"), "dest_ip": m.get("dest_ip"),
                     "image": m.get("image"),
                     "cmdline": str(m.get("cmdline") or "")[:200],
                     "description": str(m.get("description") or "")[:160]}
                    for m in matched][:8],
            })
    return findings


def _tail_text(path, max_lines: int, chunk_bytes: int = 1 << 20,
               max_bytes: int = 16 << 20) -> str:
    """Read the last `max_lines` lines without loading a whole store."""
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        end = fh.tell()
        pos = end
        data = b""
        while pos > 0 and data.count(b"\n") <= max_lines \
                and (end - pos) < max_bytes:
            step = min(chunk_bytes, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
    lines = data.splitlines()
    return b"\n".join(lines[-max_lines:]).decode("utf-8", "replace")


def scan_store(events_path, chains: list[dict] | None = None,
               max_rows: int = DEFAULT_MAX_ROWS,
               gap_seconds: int = DEFAULT_WINDOW) -> dict:
    """Scan the tail of an events store. Endpoint- and desk-safe."""
    path = Path(events_path)
    if not path.exists():
        return {"error": f"events store not found: {path}", "findings": []}
    rows = []
    # Read only a bounded tail: a production store can be tens of MB and
    # the chain scanner never needs the head of the file.
    tail = _tail_text(path, max_rows)
    for line in tail.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    findings = scan(rows[-max_rows:], chains=chains, gap_seconds=gap_seconds)
    return {"scanned_rows": min(len(rows), max_rows),
            "chains": [c["name"] for c in (chains or BUILTIN_CHAINS)],
            "findings": findings,
            "top_score": max((f["score"] for f in findings), default=0)}
