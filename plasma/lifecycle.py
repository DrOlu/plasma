"""Explicit lifecycle machines for workflows that were previously implicit.

The modules in Plasma already carry status strings in journals, ledgers and
state files. This module names those states, names the legal transitions,
and provides pure classifiers so call sites stop re-implementing the same
``if status == ...`` rules in slightly different ways.

Nothing here writes to disk. Persisted machines (update, serve request) use
``plasma.statemachine``; the classifiers are for rows that already exist.
"""

from __future__ import annotations

from .statemachine import Machine, StateError

# ---------------------------------------------------------------------------
# Machines
# ---------------------------------------------------------------------------

SERVE_REQUEST = Machine(
    name="serve_request",
    states=("received", "validated", "rejected", "running", "completed",
            "timed_out", "failed"),
    initial="received",
    terminal=("rejected", "completed", "timed_out", "failed"),
    transitions={
        "received": ("validated", "rejected"),
        "validated": ("running", "rejected"),
        "running": ("completed", "timed_out", "failed"),
        "rejected": (),
        "completed": (),
        "timed_out": (),
        "failed": (),
    },
)

PLAN = Machine(
    name="plan",
    states=("proposed", "applied", "undone", "failed"),
    initial="proposed",
    terminal=("undone", "failed"),
    transitions={
        "proposed": ("applied", "failed"),
        "applied": ("undone", "failed"),
        "undone": (),
        "failed": (),
    },
)

APPROVAL = Machine(
    name="approval",
    states=("pending", "approved", "denied", "used", "expired", "invalid"),
    initial="pending",
    terminal=("denied", "used", "expired", "invalid"),
    transitions={
        "pending": ("approved", "denied", "expired", "invalid"),
        "approved": ("used", "expired", "invalid"),
        "denied": (),
        "used": (),
        "expired": (),
        "invalid": (),
    },
)

ENFORCE = Machine(
    name="enforce",
    states=("dry-run", "pending_approval", "applied", "refused", "failed",
            "skipped"),
    initial="dry-run",
    terminal=("applied", "refused", "failed", "skipped"),
    transitions={
        "dry-run": ("pending_approval", "applied", "refused", "failed",
                    "skipped"),
        "pending_approval": ("applied", "refused", "failed", "skipped"),
        "applied": (),
        "refused": (),
        "failed": (),
        "skipped": (),
    },
)

PREVENT = Machine(
    name="prevent",
    states=("dry-run", "applied", "rolled_back", "failed"),
    initial="dry-run",
    terminal=("rolled_back", "failed"),
    transitions={
        "dry-run": ("applied", "failed"),
        "applied": ("rolled_back", "failed"),
        "rolled_back": (),
        "failed": (),
    },
)

WHIDS = Machine(
    name="whids",
    states=("Absent", "StartPending", "Running", "Stopped", "Stopping",
            "Unknown"),
    initial="Absent",
    transitions={
        "Absent": ("StartPending", "Running", "Stopped", "Unknown"),
        "StartPending": ("Running", "Stopped", "Unknown"),
        "Running": ("Stopping", "Stopped", "Unknown"),
        "Stopping": ("Stopped", "Unknown"),
        "Stopped": ("StartPending", "Running", "Unknown"),
        "Unknown": ("Absent", "StartPending", "Running", "Stopped"),
    },
)

FIM = Machine(
    name="fim",
    states=("unbaselined", "baselined", "intact", "drifted"),
    initial="unbaselined",
    transitions={
        "unbaselined": ("baselined",),
        "baselined": ("intact", "drifted"),
        "intact": ("drifted", "baselined"),
        "drifted": ("intact", "baselined"),
    },
)

CANARY = Machine(
    name="canary",
    states=("undeployed", "deployed", "intact", "tripped"),
    initial="undeployed",
    transitions={
        "undeployed": ("deployed",),
        "deployed": ("intact", "tripped"),
        "intact": ("tripped", "deployed"),
        "tripped": ("intact", "deployed"),
    },
)

DRIFT = Machine(
    name="drift",
    states=("unbaselined", "baselined", "scored"),
    initial="unbaselined",
    transitions={
        "unbaselined": ("baselined",),
        "baselined": ("scored", "baselined"),
        "scored": ("baselined", "scored"),
    },
)

IDENTITY_SCHEDULE = Machine(
    name="identity_schedule",
    states=("unscheduled", "scheduled", "running", "failed"),
    initial="unscheduled",
    transitions={
        "unscheduled": ("scheduled",),
        "scheduled": ("running", "failed", "unscheduled"),
        "running": ("scheduled", "failed"),
        "failed": ("scheduled", "unscheduled"),
    },
)

CAPTURE = Machine(
    name="capture",
    states=("idle", "running", "collected", "failed"),
    initial="idle",
    transitions={
        "idle": ("running",),
        "running": ("collected", "failed"),
        "collected": ("idle", "running"),
        "failed": ("idle", "running"),
    },
)

FLEET = Machine(
    name="fleet",
    states=("idle", "pulled", "correlated", "reported", "failed"),
    initial="idle",
    transitions={
        "idle": ("pulled", "failed"),
        "pulled": ("correlated", "failed"),
        "correlated": ("reported", "failed"),
        "reported": ("idle", "pulled"),
        "failed": ("idle", "pulled"),
    },
)

KILLSWITCH = Machine(
    name="killswitch",
    states=("off", "on"),
    initial="off",
    transitions={"off": ("on",), "on": ("off",)},
)

TENANT = Machine(
    name="tenant",
    states=("absent", "present"),
    initial="absent",
    transitions={"absent": ("present",), "present": ("absent",)},
)

RING = Machine(
    name="ring",
    states=("unassigned", "canary", "broad", "rollback"),
    initial="unassigned",
    transitions={
        "unassigned": ("canary", "broad", "rollback"),
        "canary": ("broad", "rollback"),
        "broad": ("rollback", "canary"),
        "rollback": ("canary", "broad"),
    },
)


# ---------------------------------------------------------------------------
# Classifiers for existing rows
# ---------------------------------------------------------------------------

def plan_state(row: dict) -> str:
    """Classify an actuate/playbook journal row."""
    if not isinstance(row, dict):
        return "failed"
    if row.get("action") == "undo":
        if row.get("mode") == "dry-run":
            return "proposed"
        if row.get("mode") == "applied" and row.get("ok") is not False:
            return "undone"
        return "failed"
    if row.get("mode") == "applied":
        return "applied" if row.get("ok") is not False else "failed"
    if row.get("mode") == "failed":
        return "failed"
    return "proposed"


def approval_state(row: dict) -> str:
    """Classify a ledger row in the approval lifecycle."""
    if not isinstance(row, dict):
        return "invalid"
    outcome = row.get("outcome")
    if outcome == "denied":
        return "denied"
    if outcome == "expired":
        return "expired"
    if outcome == "approval_invalid":
        return "invalid"
    if row.get("kind") == "approval_use":
        return "used"
    if row.get("kind") == "approval":
        return "approved" if row.get("approved") is True else "denied"
    if row.get("kind") == "action" and row.get("decision") == "approval_required":
        return "pending"
    return "invalid"


def enforce_state(row: dict) -> str:
    status = str((row or {}).get("status") or "")
    return status if status in ENFORCE.states else "failed"


def prevent_state(row: dict) -> str:
    status = str((row or {}).get("status") or "")
    return status if status in PREVENT.states else "failed"


def whids_state(state: str | None) -> str:
    value = str(state or "").strip()
    return value if value in WHIDS.states else "Unknown"


def fim_state(baselined: bool, findings: int = 0) -> str:
    if not baselined:
        return "unbaselined"
    return "drifted" if int(findings or 0) > 0 else "intact"


def canary_state(deployed: bool, tripped: bool = False) -> str:
    if not deployed:
        return "undeployed"
    return "tripped" if tripped else "intact"


def drift_state(baselined: bool, scored: bool = False) -> str:
    if not baselined:
        return "unbaselined"
    return "scored" if scored else "baselined"


def identity_schedule_state(installed: bool, running: bool = False,
                            failed: bool = False) -> str:
    if not installed:
        return "unscheduled"
    if failed:
        return "failed"
    return "running" if running else "scheduled"


def capture_state(status: str | None) -> str:
    value = str(status or "").strip().lower()
    if value in ("running", "started", "active"):
        return "running"
    if value in ("collected", "complete", "completed", "done"):
        return "collected"
    if value in ("failed", "error"):
        return "failed"
    return "idle"


def fleet_state(status: str | None) -> str:
    value = str(status or "").strip().lower()
    if value in ("pulled", "pull"):
        return "pulled"
    if value in ("correlated", "correlate"):
        return "correlated"
    if value in ("reported", "report"):
        return "reported"
    if value in ("failed", "error"):
        return "failed"
    return "idle"


def killswitch_state(on: bool) -> str:
    return "on" if on else "off"


def tenant_state(present: bool) -> str:
    return "present" if present else "absent"


def ring_state(ring: str | None) -> str:
    value = str(ring or "").strip().lower()
    return value if value in RING.states else "unassigned"


def require(machine: Machine, current: str, target: str) -> None:
    """Raise StateError when a transition is not legal."""
    if not machine.allows(current, target):
        raise StateError(
            f"{machine.name}: illegal transition {current!r} -> {target!r}")
