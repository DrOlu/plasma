# Security audit — 1.24.0

Scope: the Python package, CLI, MCP server, HTTP API, prevention controls and
release path at tag `v1.24.0`. This is an engineering self-audit, not an
independent penetration test or certification.

## Checks run

| Check | Result |
|---|---|
| `pytest -q -W error` | pass |
| `ruff check plasma tests` | pass |
| `bandit -r plasma` | 0 high / 0 medium; 107 low (subprocess by design) |
| `pip-audit` | no known vulnerable dependencies |
| Estate install | WS1 and WS2 on 1.24.0; release hash matches `SHA256SUMS` |

## Findings fixed

| Finding | Fix |
|---|---|
| SHA-1 used for bounded file-change heads was flagged as a security hash | Marked `usedforsecurity=False`; it is a change detector, not a signature |
| `urllib` accepted `file:` and plain-HTTP URLs | New `netguard.require_https`; all four download paths now refuse non-HTTPS, embedded credentials and control characters |
| Sysmon XML parser accepted DTD/entity input | Size cap plus explicit `<!DOCTYPE` / `<!ENTITY` refusal before parsing |
| Query regex had no length bound | 256-character cap, still compiled before use |
| Detection case files had no size/count bound | 4 MiB and 500-case caps |
| MCP `get_case` was marked read but wrote `report.md` | Report rendering is now in-memory for MCP; only CLI `case report` writes |
| Memory triage had no target cap | Hard cap of 50 targets |

## Residual risks

- `subprocess` is used deliberately to drive fixed PowerShell payloads. The
  allowlisted action model, literal quoting and plan gate are the control;
  arbitrary shell is never exposed through MCP.
- A local administrator can tamper with the event store, policy files or
  journal. Plasma detects case/report tampering and anchors the ledger, but
  it does not claim to defeat a hostile administrator.
- CFA, Network Protection and the driver blocklist can be overridden by
  policy. Apply verifies the resulting value and fails rather than claiming
  success.
- WDAC remains read-only by design.
- The estate test covers two Windows Server 2022 hosts, not every Windows
  10/11 build, domain-controller topology or high-load profile.
- No independent MITRE ATT&CK evaluation or third-party penetration test has
  been performed.

## Recommendation

Treat 1.24.0 as a hardened field release, not a certified product. Run the
prevention controls in audit mode first, keep the kill switch tested, and
review the journal after every apply/rollback drill.
