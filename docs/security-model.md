# Security model

This page states what Plasma guarantees, what it explicitly does not, and
where the trust anchors are. It is written to be useful to a reviewer, not
to a marketing page.

## Guarantees

1. **Read-only collectors; measured mutations.** Collectors and probes
   read. Mutations happen only in two measured planes:
   - **Containment** (`actuate`, driven by `plasma enforce`) — named,
     reversible actions behind a plan gate and a policy. Automatic
     containment ships armed but narrow: `snapshot` + `kill_process` at
     score 9+, with isolation and every other action behind approval.
   - **Enforcement points** (`plasma prevent`) — AppLocker, firewall,
     Defender ASR and LSA controls, audit-first, plan-gated on the rendered
     payload and rollbackable by journal id.
2. **Gate is enforced in code.** Manual applies require `--plan <dry-run
   id>` matching the action, target and payload digest. Automatic
   containment still runs through actuate's dry-run + plan gate, and only
   after a written policy allows the action and a human approves
   high/critical actions.
3. **Allowlisted actions only.** No arbitrary shell. Targets are validated
   against strict patterns; protected services, processes and accounts are
   refused before any payload runs.
4. **Lockout-resistant.**
   - `isolate_host` creates RDP-3389 and WinRM-5985 allow rules **before**
     any block rule (Windows gives specific allows precedence).
   - The installer never disables remote management.
   - `stop_service`/`kill_process`/`disable_user` refuse the management and
     security stack.
   - Health permanently checks `fDenyTSConnections` and `SecurityLayer`.
5. **Everything is journaled.** Dry-runs, applies, failures, verifications
   and undos land in `actuate-journal.jsonl`; a torn line cannot brick it.
6. **Undoable where claimed.** Actions that cannot be undone are marked
   `undoable: false` up front (`kill_process`, `rotate_credential`).
7. **Local by default.** Events stay on the host. The desk pulls bounded
   tails over the existing management channel; nothing phones home.
8. **Deterministic detection.** Detection is written rules and sequences;
   the on-device model never decides guilt and never executes anything.
9. **Bounded.** Every collector has a time window, a row cap and a size cap.

## Trust anchors

| Anchor | Where it lives | Protects |
|---|---|---|
| Payload manifest (SHA-256 per file) | inside the installed bundle | tampered sensor payloads |
| Release `SHA256SUMS` | published with each release | corrupted downloads |
| Pinned Authenticode signer | baked into the installed exe (`update.py`) | a compromised release page/repository |
| WHIDS detect-only config | `config.toml` (all action bands `report`) | the sensor acting destructively |
| Enforcement policy + journal | `config.json`, `enforce-journal.jsonl` | unattended actions exceeding policy |
| Capture-before-containment | host snapshot written before the first automatic kill | losing host state to its own response |
| Prevention journal + backups | `prevent-journal.jsonl`, `prevent-backups/` | unrecoverable policy changes |
| Sigma corpus provenance | `sigma-sources.json`, `SIGMA-DRL-1.1.md` | untraceable or mislicensed detection content |
| Telemetry provenance | `sysmon-config.xml` → coverage `telemetry` | claiming coverage from rules that cannot fire |
| Refusal gate (`GATE_VERSION 1`) | frozen instance | the model guessing instead of refusing |

## Plugin trust model

A plugin is code you chose to run. Plasma reduces the blast radius but does not
make an untrusted plugin safe.

- **Signature and digest.** Install verifies the payload digest and an Ed25519
  signature against an embedded key; pass `--pubkey` to pin a publisher.
  `plugin verify` recomputes the digest and exits 2 on any change. Unsigned
  installs require `--allow-unsigned`.
- **No store write.** Plugins emit records; the host validates, stamps the
  source, dedupes and appends. A plugin cannot forge another sensor.
- **No shell.** Responders declare argv arrays. Plasma owns the plan id, the
  reason requirement, the kill switch, the journal and the rollback.
- **Declared roots.** Path arguments in responder actions are confined to
  `permissions.filesystem`.
- **Resource caps.** Line size, event count, timeout and stderr size are
  enforced; ten invalid records quarantine the run.
- **Process isolation.** A plugin runs as a child process with its own working
  directory. Job Objects/AppContainer isolation is the next hardening step.
- **Secrets.** Injected as environment variables at start; never written to the
  manifest, registry or logs.
- **No core mutation.** Plugins cannot change config, rules, baselines or
  services. A compromised plugin can emit false data; it cannot disable Plasma.

## Threat model boundaries

**In scope for detection:**

- commodity post-exploitation, living-off-the-land, credential access,
  persistence, lateral movement, logon abuse, data-staging indicators;
- persistence inventory and signature anomalies (deep probe);
- image/process-level events (Sysmon), script-block content (tap),
  identity events (Security channel).

**Explicitly out of scope (today):**

- **Inline blocking from a Plasma driver.** Plasma ships no minifilter,
  WFP callout or process-veto driver. Prevention is delivered through
  Windows enforcement points (AppLocker, firewall, Defender ASR, LSA
  protection) configured by `plasma prevent`, plus containment actions.
  A process can therefore execute once before containment.
- **Kernel-level self-protection.** There is no Plasma driver; a
  local administrator can stop the services. (Sysmon and WHIDS can be
  protected by their own mechanisms, but Plasma does not claim tamper-proof
  operation against a determined admin.)
- **Full memory forensics.** No LSASS/host memory acquisition. The deep
  probe and syscall-level evidence are as far as it goes; DTrace integration
  is a roadmap item, not a claim.
- **Ransomware impact (T1486).** Detected through **canary files**
  (`plasma canary deploy`, verified on every `watch`): a missing or modified
  decoy is a score-10 finding. This is deliberately not an "encryption
  burst" heuristic; the coverage report attributes the technique to
  `canary:verify`. DNS and HTTP tokens add access/recon tripwires without
  cloud callbacks; HTTP tokens use a loopback-first local collector.
- **Endpoint DLP / content inspection.** Not attempted.
- **Memory scanning is point-in-time.** HollowsHunter/PE-sieve is a
  user-mode probe, not a kernel monitor. It can miss a short-lived implant
  between scans, cannot read every protected process and may produce
  managed-JIT noise; Plasma suppresses that specific class. Dumps are
  opt-in, local and sensitive.
- **Kernel interception.** Plasma compiles policy into NTFS ACLs, Windows
  Firewall and the MCP boundary. It does not ship a minifilter, WFP callout
  or API hook; kernel-mode malware and direct syscalls remain outside the
  claim.

## Data handling

- Events: JSONL on the endpoint, rotation/compaction under operator control.
- Identity: SIDs/usernames as Windows reports them; machine accounts
  dropped.
- Alerts: Telegram/webhook payloads include finding text — no raw event
  bodies by default; paths/usernames may appear in descriptions.
- Fleet: passwords only via environment variables (`password_env`);
  inline secrets in inventory or notify configs are refused.
- Response: `rotate_credential` prints the new password once and never
  writes it to the journal.

## Estate ledger data handling

`plasma estate build` runs on the endpoint and reduces a bounded window to
counts. The ledger contains account names, first/last timestamps, bounded
source addresses, logon types, `user>process` pairs and file hashes. It does
**not** contain command lines, file paths, event descriptions or the event
rows themselves. Machine and service accounts are excluded.

Every ledger carries a SHA-256 over its canonical body. `plasma estate load`,
`merge --dir` and `status` recompute it and refuse a modified ledger. This is
an integrity check, **not a signature**: it detects corruption and casual
edits, while the trust boundary remains the desk's filesystem ACL and the
WinRM channel. The desk stores one current ledger per host under `hosts/` and
replaces it on each pull; retention is an explicit copy, not an implicit
history. Transport to the desk is WinRM (HTTPS recommended) or a local file
for air-gapped estates.

The `coverage` block adds event counts, event kinds, last-seen timestamps and
the result of the last identity pull — including its error string, which can
name a channel or RPC failure but carries no credentials. The marker lives
beside the store as `<events-dir>\identity-pull.json` and is replaced on every
pull attempt.

## Update integrity

From 1.2.0 the update path verifies **two independent anchors**: the
published SHA-256 and the pinned signer thumbprint. A release that is not
signed by a pinned certificate is refused before execution. The default pin
is the project's self-signed certificate; the SignPath Foundation
thumbprint will be added when that application is approved.

## Verification posture

- 264 automated tests, including detection-content tests that require every
  gene rule to compile **and** behave on positive/negative cases.
- CI runs the test matrix on Linux and Windows, compiles the ETW tap and
  self-tests it, builds the single-file exe and smoke-tests it.
- Golden gates verify the frozen instance's probe answers before release.

If you find a defect, open an issue on
[GitHub](https://github.com/DrOlu/plasma/issues) with the command, the
output and the expected behavior.

## Secure defaults (1.9.0)

- The Plasma root is restricted to SYSTEM and Administrators at install
  (well-known SIDs, so it works on non-English Windows). Policy,
  kill-switch state, approvals, ledger and events are not readable by
  standard users.
- Credential-bearing command lines are redacted at WHIDS normalization;
  `plasma store redact --events <path>` migrates an older store.
- MCP tenant and scopes come from `PLASMA_TENANT` / `PLASMA_SCOPES`, not
  from the caller's `_meta`; client claims require
  `PLASMA_TRUST_CLIENT_META=1`. Read tools are tenant-filtered.
- WinRM fleet transport requires HTTPS unless `allow_insecure_winrm: true`
  is set for a controlled lab.
- The DTrace MSI is executed only after a valid Microsoft Authenticode
  signature check.
- HTTP webhook notification URLs are refused; Telegram tokens are redacted
  from error strings.
