"""Explicit lifecycle machines and classifiers."""

import pytest

from plasma import lifecycle
from plasma.statemachine import StateError


def test_serve_request_happy_path():
    state = "received"
    for target in ("validated", "running", "completed"):
        lifecycle.require(lifecycle.SERVE_REQUEST, state, target)
        state = target
    assert state == "completed"


def test_serve_request_rejects_illegal_transition():
    with pytest.raises(StateError):
        lifecycle.require(lifecycle.SERVE_REQUEST, "received", "completed")
    with pytest.raises(StateError):
        lifecycle.require(lifecycle.SERVE_REQUEST, "completed", "running")


def test_plan_machine():
    assert lifecycle.PLAN.allows("proposed", "applied")
    assert lifecycle.PLAN.allows("applied", "undone")
    assert not lifecycle.PLAN.allows("proposed", "undone")
    assert not lifecycle.PLAN.allows("undone", "applied")


def test_approval_machine():
    assert lifecycle.APPROVAL.allows("pending", "approved")
    assert lifecycle.APPROVAL.allows("approved", "used")
    assert not lifecycle.APPROVAL.allows("denied", "used")
    assert not lifecycle.APPROVAL.allows("used", "approved")


def test_enforce_and_prevent_machines():
    assert lifecycle.ENFORCE.allows("dry-run", "pending_approval")
    assert lifecycle.ENFORCE.allows("pending_approval", "applied")
    assert not lifecycle.ENFORCE.allows("applied", "pending_approval")
    assert lifecycle.PREVENT.allows("dry-run", "applied")
    assert lifecycle.PREVENT.allows("applied", "rolled_back")
    assert not lifecycle.PREVENT.allows("rolled_back", "applied")


def test_whids_machine():
    assert lifecycle.WHIDS.allows("StartPending", "Running")
    assert lifecycle.WHIDS.allows("Running", "Stopping")
    assert not lifecycle.WHIDS.allows("Absent", "Stopping")


def test_fim_canary_drift_machines():
    assert lifecycle.FIM.allows("unbaselined", "baselined")
    assert lifecycle.FIM.allows("baselined", "drifted")
    assert lifecycle.CANARY.allows("deployed", "tripped")
    assert lifecycle.DRIFT.allows("baselined", "scored")


def test_identity_capture_fleet_machines():
    assert lifecycle.IDENTITY_SCHEDULE.allows("unscheduled", "scheduled")
    assert lifecycle.IDENTITY_SCHEDULE.allows("scheduled", "running")
    assert lifecycle.CAPTURE.allows("idle", "running")
    assert lifecycle.CAPTURE.allows("running", "collected")
    assert lifecycle.FLEET.allows("idle", "pulled")
    assert lifecycle.FLEET.allows("pulled", "correlated")
    assert lifecycle.FLEET.allows("correlated", "reported")


def test_killswitch_tenant_ring_machines():
    assert lifecycle.KILLSWITCH.allows("off", "on")
    assert lifecycle.KILLSWITCH.allows("on", "off")
    assert lifecycle.TENANT.allows("absent", "present")
    assert lifecycle.RING.allows("unassigned", "canary")
    assert lifecycle.RING.allows("canary", "broad")
    assert not lifecycle.RING.allows("broad", "unassigned")


# ---------------------------------------------------------------------------
# classifiers
# ---------------------------------------------------------------------------

def test_plan_state():
    assert lifecycle.plan_state({"mode": "dry-run"}) == "proposed"
    assert lifecycle.plan_state({"mode": "applied", "ok": True}) == "applied"
    assert lifecycle.plan_state({"mode": "applied", "ok": False}) == "failed"
    assert lifecycle.plan_state({"action": "undo", "mode": "dry-run"}) == "proposed"
    assert lifecycle.plan_state({"action": "undo", "mode": "applied",
                                 "ok": True}) == "undone"
    assert lifecycle.plan_state({"action": "undo", "mode": "applied",
                                 "ok": False}) == "failed"
    assert lifecycle.plan_state(None) == "failed"


def test_approval_state():
    assert lifecycle.approval_state(
        {"kind": "action", "decision": "approval_required"}) == "pending"
    assert lifecycle.approval_state(
        {"kind": "approval", "approved": True}) == "approved"
    assert lifecycle.approval_state(
        {"kind": "approval", "approved": False}) == "denied"
    assert lifecycle.approval_state({"kind": "approval_use"}) == "used"
    assert lifecycle.approval_state({"outcome": "denied"}) == "denied"
    assert lifecycle.approval_state({"outcome": "expired"}) == "expired"
    assert lifecycle.approval_state({"outcome": "approval_invalid"}) == "invalid"
    assert lifecycle.approval_state(None) == "invalid"


def test_enforce_and_prevent_state():
    assert lifecycle.enforce_state({"status": "pending_approval"}) == "pending_approval"
    assert lifecycle.enforce_state({"status": "applied"}) == "applied"
    assert lifecycle.enforce_state({"status": "bogus"}) == "failed"
    assert lifecycle.prevent_state({"status": "dry-run"}) == "dry-run"
    assert lifecycle.prevent_state({"status": "rolled_back"}) == "rolled_back"
    assert lifecycle.prevent_state({"status": "bogus"}) == "failed"


def test_whids_state():
    assert lifecycle.whids_state("Running") == "Running"
    assert lifecycle.whids_state("StartPending") == "StartPending"
    assert lifecycle.whids_state("") == "Unknown"
    assert lifecycle.whids_state("bogus") == "Unknown"


def test_fim_canary_drift_state():
    assert lifecycle.fim_state(False) == "unbaselined"
    assert lifecycle.fim_state(True, 0) == "intact"
    assert lifecycle.fim_state(True, 2) == "drifted"
    assert lifecycle.canary_state(False) == "undeployed"
    assert lifecycle.canary_state(True, False) == "intact"
    assert lifecycle.canary_state(True, True) == "tripped"
    assert lifecycle.drift_state(False) == "unbaselined"
    assert lifecycle.drift_state(True, False) == "baselined"
    assert lifecycle.drift_state(True, True) == "scored"


def test_identity_capture_fleet_state():
    assert lifecycle.identity_schedule_state(False) == "unscheduled"
    assert lifecycle.identity_schedule_state(True, False) == "scheduled"
    assert lifecycle.identity_schedule_state(True, True) == "running"
    assert lifecycle.identity_schedule_state(True, False, True) == "failed"
    assert lifecycle.capture_state("running") == "running"
    assert lifecycle.capture_state("collected") == "collected"
    assert lifecycle.capture_state("bogus") == "idle"
    assert lifecycle.fleet_state("pulled") == "pulled"
    assert lifecycle.fleet_state("correlated") == "correlated"
    assert lifecycle.fleet_state("reported") == "reported"
    assert lifecycle.fleet_state("bogus") == "idle"


def test_killswitch_tenant_ring_state():
    assert lifecycle.killswitch_state(True) == "on"
    assert lifecycle.killswitch_state(False) == "off"
    assert lifecycle.tenant_state(True) == "present"
    assert lifecycle.tenant_state(False) == "absent"
    assert lifecycle.ring_state("canary") == "canary"
    assert lifecycle.ring_state("bogus") == "unassigned"
