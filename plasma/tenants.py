"""Tenant registry for MSSP / multi-estate isolation.

A tenant is a named group of hosts. Ledger rows carry the tenant so an
MSSP can prove separation, and policy checks can scope an agent to one
tenant without changing the harness.
"""

from __future__ import annotations

from pathlib import Path

from . import agentstate

TENANTS_FILE = "tenants.json"
DEFAULT_TENANT = "default"


def path(root=None) -> Path:
    return agentstate.base(root) / TENANTS_FILE


def _host(value) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _load(root) -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    if not isinstance(data, dict):
        raise TypeError("tenants.json is not an object")
    tenants = data.get("tenants")
    if tenants is None:
        tenants = {}
    if not isinstance(tenants, dict):
        raise TypeError("tenants.json 'tenants' is not an object")
    tenants.setdefault(DEFAULT_TENANT, {"name": "Default", "hosts": []})
    for tenant_id, value in list(tenants.items()):
        if not isinstance(value, dict):
            raise TypeError(f"tenant {tenant_id!r} is not an object")
        value["hosts"] = sorted({_host(h) for h in (value.get("hosts") or [])
                                 if _host(h)})
    return {"version": 1, "tenants": tenants}


def _save(root, data: dict) -> dict:
    agentstate.write_json(path(root), data)
    return data


def list_tenants(root=None) -> list[dict]:
    data = _load(root)
    out = []
    for tenant_id, value in sorted(data["tenants"].items()):
        hosts = sorted(set(value.get("hosts") or []))
        out.append({"id": tenant_id, "name": value.get("name", tenant_id),
                    "hosts": hosts})
    return out


def add(root, tenant: str, name: str = "", hosts=None) -> dict:
    if not tenant or not tenant.replace("-", "").replace("_", "").isalnum():
        raise ValueError("tenant id must be alphanumeric, dash or underscore")
    with agentstate.lock(path(root).with_suffix(".lock"), stale=300):
        data = _load(root)
        incoming = {_host(h) for h in (hosts or []) if _host(h)}
        # Host ownership is exclusive: moving a host to a tenant removes it
        # from every other tenant, so resolve() can never be ambiguous.
        for other_id, other in data["tenants"].items():
            if other_id != tenant:
                other["hosts"] = sorted(set(other.get("hosts") or []) - incoming)
        current = data["tenants"].get(tenant, {"name": name or tenant, "hosts": []})
        current["name"] = name or current.get("name") or tenant
        merged = set(current.get("hosts") or [])
        merged.update(incoming)
        current["hosts"] = sorted(merged)
        data["tenants"][tenant] = current
        _save(root, data)
        return {"id": tenant, "name": current["name"], "hosts": current["hosts"]}


def remove(root, tenant: str) -> dict:
    if tenant == DEFAULT_TENANT:
        raise ValueError("the default tenant cannot be removed")
    with agentstate.lock(path(root).with_suffix(".lock"), stale=300):
        data = _load(root)
        if tenant not in data["tenants"]:
            raise KeyError(tenant)
        data["tenants"].pop(tenant)
        _save(root, data)
    return {"removed": tenant}


def resolve(root=None, host: str | None = None) -> str:
    if not host:
        return DEFAULT_TENANT
    wanted = _host(host)
    try:
        rows = list_tenants(root)
    except (TypeError, ValueError):
        # A corrupt registry must not collapse every host into default.
        return "__invalid__"
    for row in rows:
        if wanted in {_host(h) for h in row["hosts"]}:
            return row["id"]
    return DEFAULT_TENANT


def allows(root=None, tenant: str | None = None, host: str | None = None) -> bool:
    if not tenant:
        return True
    resolved = resolve(root, host)
    return resolved not in (None, "", "__invalid__") and resolved == tenant