# Plasma security posture

## Design rules

1. **Read-only instance.** Every probe in the frozen menu is a query. There is
   no write, kill, block or isolate probe in the instance. Response lives in
   WHIDS's deterministic policy layer (deployed detect-only, see below) and
   in the `plasma actuate` module — which is human-invoked, allowlisted,
   dry-run-first, journaled with verified undo, and lockout-proof
   (protected services/processes/accounts are refused; `isolate_host` keeps
   RDP 3389 + WinRM 5985 reachable by design).
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
6. **Bundled third-party payloads are covered by the bundle manifest.**
   The WHIDS payload (AGPL-3.0) ships with its LICENSE beside it; the installer
   refuses to deploy a tampered payload.
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
| Response overreach | no response probes by default; WHIDS governs its own actions; human approval for advisories |
| Sensor tampering | WHIDS is the required sensor; Sysmon is a required dependency; post-install verification detects blindness |

## Intelligence writes to WHIDS

`plasma whids push` changes a gene rule file WHIDS compiles, so it is treated
as a response-adjacent action:

* **dry-run by default** — `--apply` is required;
* only indicators at/above `--min-confidence` (gene 0-10 scale, default 8);
* private, loopback, link-local, multicast and reserved IPs are refused;
* benign domain suffixes (Microsoft/Office/Google/Cloudflare/local) are refused;
* the existing rule file is backed up and its expressions merged, never
  overwritten blindly;
* every apply is journaled with rule hash, counts, reason and service result;
* WHIDS response actions (kill/dump/quarantine) remain governed by WHIDS
  itself — Plasma generates detection rules only.

## Operational cautions

* Test on non-production endpoints first. WHIDS actionable rules can terminate processes.
* Monitor coverage: a drop below 95% means the sensor/normalizer schema
  drifted, and probes may silently mis-answer.
* Restrict the local ask surface to loopback if wrapped in a service.
* Rotate and sign release artifacts; verify `SHA256SUMS` on the endpoint.
* Legal: deploy only on endpoints you administer, with notice/consent where
  required. Sysmon is installed under Microsoft's EULA, not redistributed.

## Detect-only WHIDS (no kill sensors)

Plasma ships WHIDS in **detect-only mode**: the `[actions]` section of
`whids.toml` restricts every criticality band to `["report"]`, and the Plasma
gene rule carries `"Actions": ["report"]`. WHIDS therefore:

- raises alerts (JSONL in `Logs\Alerts`) — nothing more;
- **cannot** kill processes, blacklist indicators, dump memory, or modify the
  network — no matter what any rule or event criticality requests;
- cannot be the cause of a lockout (its actions cannot touch services,
  remote access, or the firewall).

This was a deliberate design decision after Sentinel 3.3.1's always-on
hardening + remote-session guard locked remote operators out of a host.
If kill/dump actions are ever wanted, they must be enabled deliberately in
`whids.toml` by the operator, never by default.
