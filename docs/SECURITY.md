# Plasma security posture

## Design rules

1. **Read-only instance.** Every probe in the frozen menu is a query. There is
   no write, kill, block or isolate probe. Response lives in Sentinel's
   deterministic policy layer.
2. **Model out of the control path.** neuralOS selects a probe and fills
   arguments. It never executes anything and never authorizes a response. Any
   model-suggested action (future work) must sit behind an allowlist, a
   dry-run, a journal and human approval.
3. **Frozen artifacts.** The bundle is versioned and hash-manifested. The
   installer verifies every file before staging; a tampered menu or bridge is
   rejected.
4. **No secrets in the instance.** Credentials (if ever needed) belong in the
   executor via environment variables or Windows Credential Manager, never in
   model-facing arguments or the bundle.
5. **Capped answers.** 25 rows plus counts; the model sees digests, not dumps.
   No log lake is created by the instance.
6. **Bundled third-party payloads are verified twice.** The Sentinel setup EXE
   is covered by the bundle manifest (SHA256) and by its own pin file. The
   installer refuses to execute it on a hash mismatch. The MIT LICENSE and the
   upstream SHA256SUMS travel beside the payload.
7. **The standalone executable embeds its runtime.** PyInstaller bundles Python
   and Pydantic into one signed-able binary; it executes the bundle's bridge in
   its own process, so no system Python is needed and no interpreter is exposed.

## Threat model

| Threat | Mitigation |
|---|---|
| Tampered bundle at install | SHA256 manifest, installer exit 2, signed releases recommended |
| Hostile log content steering the model | constrained grammar, disjoint triggers, digests, validation of every record |
| Model hallucinating a probe | engine selects from the menu only; bridge rejects unknown tools |
| Endpoint without Python | `bridge.ps1` with generated shape checks; same caps and contract |
| Response overreach | no response probes by default; Sentinel Tier-1 only; human approval for advisories |
| Sensor tampering | Sentinel is the required sensor; optional Sysmon gives an independent baseline; post-install verification detects blindness |

## Operational cautions

* Test on non-production endpoints first. Sentinel can terminate processes.
* Monitor coverage: a drop below 95% means the sensor/normalizer schema
  drifted, and probes may silently mis-answer.
* Restrict the local ask surface to loopback if wrapped in a service.
* Rotate and sign release artifacts; verify `SHA256SUMS` on the endpoint.
* Legal: deploy only on endpoints you administer, with notice/consent where
  required. Sysmon is installed under Microsoft's EULA, not redistributed.
