# Compliance evidence

`plasma evidence export` turns the node's real state into an auditor-readable
control matrix. It does **not** certify anything; it produces the evidence a
human auditor can verify.

```powershell
plasma evidence export --framework cbn ndpa pci iso27001 --out evidence.json
```

Outputs:

- `evidence.json` — machine-readable controls, statuses and evidence.
- `evidence.md` — the same matrix as Markdown.

## What is measured

| Input | Evidence |
|---|---|
| Event store | rows, kinds, hosts, first/last UTC timestamp |
| Coverage | rollup / exact / weighted percentages and blind spots |
| Policy | autonomy tier, deny list, blast radius, rate limit |
| Ledger | hash-chain verification, rows, pending approvals |
| Kill switch | global and per-host state |
| Tenants | configured tenants and host assignment |
| Response | chains, canaries, plan-gated action tools |

## Frameworks

- **CBN** — policy, asset visibility, monitoring, incident response, least
  privilege, third-party/agent governance, data residency, resilience.
- **NDPA** — minimisation, safeguards, breach detection, accountability,
  local processing, retention.
- **PCI DSS v4.0** — audit logging, record contents, review, retention, time
  sync, change detection, incident response.
- **ISO 27001:2022** — logging, monitoring, incident management, assessment,
  configuration management, privileged access.

Each control is marked `met`, `partial` or `gap`. Gaps are shown, not hidden.

## Honest caveats

- Evidence is only as good as the deployed configuration and the ledger.
- A control marked `met` means the mechanism exists and has evidence; it is
  not an audit opinion.
- Some controls depend on organisational policy outside Plasma (training,
  supplier contracts, business continuity).
- Coverage is the shipped-rule view: 91.7% rollup with three named blind
  spots (T1056, T1056.001, T1112).
- Have counsel map the output to the current CBN/NDPA/PCI/ISO requirements
  before submitting it to a regulator.
