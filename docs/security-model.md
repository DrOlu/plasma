# Security model

This page states what Plasma guarantees, what it explicitly does not, and
where the trust anchors are. It is written to be useful to a reviewer, not
to a marketing page.

## Guarantees

1. **Read-only first.** Collectors and probes read. The only mutations come
   from `actuate`, and only behind a dry-run + plan gate.
2. **Human gate is enforced in code.** `--apply` without `--plan <dry-run
   id>` is refused; the plan must match the action, the target and the
   rendered payload digest.
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
| WHIDS detect-only config | `config.toml` (all action bands `report`) | the EDR acting destructively |
| Refusal gate (`GATE_VERSION 1`) | frozen instance | the model guessing instead of refusing |

## Threat model boundaries

**In scope for detection:**

- commodity post-exploitation, living-off-the-land, credential access,
  persistence, lateral movement, logon abuse, data-staging indicators;
- persistence inventory and signature anomalies (deep probe);
- image/process-level events (Sysmon), script-block content (tap),
  identity events (Security channel).

**Explicitly out of scope (today):**

- **Real-time blocking.** Plasma does not stop process execution or
  interrupt syscalls. It detects and responds with named actions.
- **Kernel-level self-protection.** There is no Plasma driver; a
  local administrator can stop the services. (Sysmon and WHIDS can be
  protected by their own mechanisms, but Plasma does not claim tamper-proof
  operation against a determined admin.)
- **Full memory forensics.** No LSASS/host memory acquisition. The deep
  probe and syscall-level evidence are as far as it goes; DTrace integration
  is a roadmap item, not a claim.
- **Ransomware staging (T1486).** The coverage report says it plainly: no
  rule watches it today. Chain detection and file-telemetry rules are the
  planned closure.
- **Endpoint DLP / content inspection.** Not attempted.

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
