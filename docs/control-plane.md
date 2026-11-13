# Control plane

The control plane is deliberately small: policy, approvals, provenance,
kill switch, tenants, rings and rollback. It is CLI-first and JSON-out, so
an agent or a human can drive it. There are no dashboards to maintain.

All commands accept `--root`; the default is `C:\ProgramData\Plasma` on
Windows and `~/.plasma` elsewhere.

## Policy

```powershell
plasma control policy show
plasma control policy set --autonomy assist|supervised|autonomous
plasma control policy set --deny kill_process --deny isolate_host
plasma control policy set --allow deploy_canary
plasma control policy set --max-actions 20 --max-hosts 1
plasma control policy set --allow-critical      # autonomous only
```

The policy is written to `policy.json` and checked before every tool call.

## Approvals

```powershell
plasma control approvals list [--limit N]
plasma control approvals approve <id> [--approver NAME] [--note TEXT]
plasma control approvals deny <id> [--approver NAME] [--note TEXT]
```

Approvals are single-use and bound to the tool and argument hash.

## Audit

```powershell
plasma control audit tail --last 50
plasma control audit verify
```

`verify` returns exit `2` when the hash chain is broken.

## Kill switch

```powershell
plasma control killswitch status
plasma control killswitch on [--host WS1] --reason "incident"
plasma control killswitch off [--host WS1]
```

Reads stay available; actions are blocked.

## Tenants

```powershell
plasma control tenants list
plasma control tenants add acme --name "Acme Bank" --host WS9 --host WS10
plasma control tenants remove acme
```

Tenants scope hosts and tag ledger rows for MSSP separation.

## Deployment rings

```powershell
plasma ring status
plasma ring assign WS1 --ring canary
plasma ring promote canary
```

`update apply --ring canary` refuses a host that is not in that ring. Rings
are local facts; an agent can read them but should not assign them.

## Rollback

```powershell
plasma rollback [--bin PATH]
```

Restores the previous canonical binary (`<bin>.old`) and keeps the failed
one as `<bin>.failed`.

## Evidence and assurance

```powershell
plasma evidence export --framework cbn ndpa pci iso27001 --out evidence.json
plasma assurance sbom --out sbom.json
plasma assurance safety-case --out safety-case.md
plasma assurance support-bundle --out support.zip
plasma assurance notices
plasma eval run
```

- `evidence export` writes JSON and a Markdown control matrix.
- `assurance sbom` writes a CycloneDX 1.5 document.
- `safety-case` embeds the eval result and the known limits.
- `support-bundle` contains policy, ledger tail, health, coverage and system
  facts; it contains no passwords or API tokens.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success / clean |
| 1 | input or data error |
| 2 | refused, approval needed, or verification failed |
| 3 | execution failure |
