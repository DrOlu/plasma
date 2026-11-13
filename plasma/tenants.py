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


def _load(root) -> dict:
    data = agentstate.read_json(path(root), {}) or {}
    tenants = data.get("tenants")
    if not isinstance(tenants, dict) or not tenants:
        return {"version": 1,
                "tenants": {DEFAULT_TENANT: {"name": "Default", "hosts": []}}}
    tenants.setdefault(DEFAULT_TENANT, {"name": "Default", "hosts": []})
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
    data = _load(root)
    incoming = set(hosts or [])
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
    data = _load(root)
    if tenant not in data["tenants"]:
        raise KeyError(tenant)
    data["tenants"].pop(tenant)
    _save(root, data)
    return {"removed": tenant}


def resolve(root=None, host: str | None = None) -> str:
    if not host:
        return DEFAULT_TENANT
    for row in list_tenants(root):
        if host in row["hosts"]:
            return row["id"]
    return DEFAULT_TENANT


def allows(root=None, tenant: str | None = None, host: str | None = None) -> bool:
    if not tenant:
        return True
    return resolve(root, host) == tenant