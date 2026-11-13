# Assurance

Autonomy raises the burden of proof. These artifacts are the minimum a
security-conscious buyer should ask for, and the minimum Plasma should
produce on every release.

## SBOM

```powershell
plasma assurance sbom --out sbom.json
```

CycloneDX 1.5. Includes Plasma (MIT), the bundled WHIDS payload (AGPL-3.0),
pydantic, pydantic-core, the optional pywinrm dependency and the frozen
neuralOS engine/model entry. Use it for vendor-risk review and dependency
tracking.

## Safety case

```powershell
plasma assurance safety-case --out safety-case.md
```

States the claim, the controls, the eval result and the known limits:

- typed tools with scopes and risk tiers;
- dry-run-only mutating tools in MCP;
- high/critical approval;
- blast-radius and rate limits;
- hash-chained provenance;
- kill switch;
- no arbitrary shell;
- eval suite passing.

## Support bundle

```powershell
plasma assurance support-bundle --out support.zip
```

A redacted diagnostic archive: config, policy, kill switch, tenants, rings,
ledger tail, ledger verification, health, coverage and system facts. It
excludes passwords, API tokens and event content beyond the ledger tail.

## Evaluation

```powershell
plasma eval run
```

Safety scenarios, not detection tests. Exit `2` on any failure. Run it in CI
and before raising an estate's autonomy tier.

## Third-party notices

```powershell
plasma assurance notices
```

Plasma is MIT. The bundled WHIDS payload is AGPL-3.0. If you modify and
distribute WHIDS, comply with the AGPL; get counsel before OEM packaging.

## What to ask from the vendor

- SBOM for the release you are running.
- Pen-test report or a current assessment.
- Safety case and eval results.
- DPA, SLA, support model and escalation path.
- Cyber-liability insurance.
- A documented rollback and incident drill.
- Proof that data stays on the estate.
