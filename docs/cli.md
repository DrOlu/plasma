# CLI reference

Every command prints JSON. Exit codes are part of the contract:
`0` success/clean, `1` data or input error, `2` refused/attention needed,
`3` execution or verification failure.

## Endpoint commands

### install

```text
plasma install [--dry-run] [--force] [--root PATH] [--skip-whids]
              [--skip-sysmon-check] [--require-whids]
```

Intelligent installer: verifies the payload manifest, decides FULL/MINIMAL,
installs Sysmon when possible, provisions WHIDS, writes `config.json`, flips
the `current` junction, and reports the decision. `--require-whids` makes a
degraded decision fail with exit 3.

### health / status / probe / ask

```text
plasma health [--root PATH]
plasma status [--events FILE]
plasma probe --tool NAME --events FILE
plasma ask --prompt "..." --events FILE
```

`health` = checks + verdict. `status` = bundle identity + probe menu.
`probe`/`ask` = run one named probe, or let the on-device model choose one.
Refusals are structured, never guesses.

### identity

```text
plasma identity pull --events FILE [--host NAME] [--since MINUTES]
                     [--ids LIST] [--max-events N]
```

Reads the Security channel through the Event Log API, UTC-normalized,
deduped and bounded (`--max-events`, default 2000).

| Event | Kind | What it gives you |
|---|---|---|
| 4624 / 4625 | `auth` | logon success / failure, type, source, workstation |
| 4768 / 4769 / 4770 / 4771 | `auth` | Kerberos TGT, service ticket, renewal, pre-auth failure (KDC only — zero on a member server, reported as zero) |
| 4776 | `auth` | NTLM credential validation |
| 4688 | `process` | process creation with creator subject, parent image and command line (when audit policy records it) |

`--ids` takes a comma list from that set and is allowlisted: anything else is
rejected before PowerShell is invoked.

### whids

```text
plasma whids pull    --root DIR --out FILE
plasma whids push    --events FILE [--min-confidence N] [--max-indicators N] [--apply] [--reason TEXT]
plasma whids status  --root DIR --events FILE
plasma whids diagnose [--root DIR]
plasma whids ensure  [--root DIR] [--wait SECONDS]
```

`push` is dry-run by default; `--apply` replaces `plasma-iocs.gen`
atomically. Default confidence is 8 on the gene 0–10 scale.

`ensure` is the watchdog body: Running is a no-op; a hung `StartPending` is
force-stopped and restarted; a stopped service is started. Actions are
appended to `logs/whids-watchdog.log`. The installer registers
`PlasmaWhidsWatchdog` (SYSTEM, every 2 minutes) to run it.

### trace

```text
plasma trace list
plasma trace check
plasma trace selftest [--root DIR]
plasma trace run <script> --events FILE [--for 5s] [--max-rows N] [--out FILE]
plasma trace provision
```

Reviewed, bounded DTrace runs normalized into the event store.
`provision` installs the Microsoft package (direct MSI when winget is
absent), enables `bcdedit /set dtrace on`, and reports
`reboot_required: true`. Installed + enabled is ready; versions are not
chased. Scripts emit `tid` for estate portability.

### tap

```text
plasma tap list
plasma tap selftest [--rules FILE] [--tap-exe PATH]
plasma tap run [--providers LIST] [--for DURATION] [--max-matches N] [--out-dir DIR]
```

Bounded live ETW window. Exit 3 = the session could not start.

### deep

```text
plasma deep persistence [--json-out FILE] [--cap N]
```

One bounded pass over every auto-start location with Authenticode status.

### watch / notify

```text
plasma watch once
plasma watch loop --every SECONDS
plasma notify show [--root PATH]
plasma notify test [--root PATH] [--host NAME]
```

`watch` = health + drift + new alerts + chains → verdict; exits non-zero
when findings exist. `notify` validates and tests delivery channels.

### drift

```text
plasma drift record QUESTION [--root PATH] [--canary ACCOUNT...]
plasma drift score  QUESTION [--root PATH]
plasma drift list   [--root PATH]
```

`record` snapshots; `score` diffs (exit 2 on drift, 1 on collection error).

### chain / store / coverage

```text
plasma chain score --events FILE [--window SECONDS] [--max-rows N]
plasma store rotate  --events FILE [--max-mb N] [--keep N]
plasma store compact --events FILE [--out FILE]
plasma store stats   --events FILE
plasma coverage [--sensors DIR]
```

Chains scan the tail; store commands keep the diary bounded; coverage
reports ATT&CK coverage incl. blind spots.

### observe

```text
plasma observe attest|sketch|edges|explain|pslogs|attackmap|...
```

Read-only self-knowledge questions (identity surface, logon edges, network
edges, PowerShell logs, attack map). `attest` includes the blind check.

## Desk-side commands

### fleet

```text
plasma fleet pull      --inventory FILE --case NAME [--cap N] [--window SECONDS] [--canary ACCOUNT...]
plasma fleet correlate --case NAME [--window SECONDS]
plasma fleet report    --case NAME
```

Correlates lateral hops, shared indicators, canaries and blind hosts.

### actuate / playbook

```text
plasma actuate apply <action> [--target T] --reason TEXT [--apply --plan ID]
plasma actuate undo  --id ID [--apply]
plasma actuate journal [--last N]
plasma actuate apply --list
plasma playbook list
plasma playbook apply <name> [--target T] --reason TEXT [--apply --plan ID]
plasma playbook undo  --id ID [--apply]
```

`--apply` requires `--plan` from a seen dry-run of the same action + target.

### enforce

```text
plasma enforce run [--root DIR] [--apply | --dry-run]
plasma enforce status
plasma enforce pending
plasma enforce approve --id ID [--apply]
```

Tier 0 prevention: findings become allowlisted, reversible containment.
Armed by default but narrow: `snapshot` + `kill_process` at score 9+, a
2-action per-run cap and a 30-minute cooldown; isolation and every other
action require approval. The policy still gates each action. The installer
registers `PlasmaWatch`, which runs `plasma watch once --enforce` every
5 minutes.

### protect

```text
plasma protect status
plasma protect protected
plasma protect arm [--apply-prevention --reason TEXT]
plasma protect disarm [--reason TEXT]
```

Inspect or change the measured posture. `arm` writes the measured
enforcement block; `disarm` sets `enabled: false` and `mode: "dry-run"`.
`protected` lists the services, processes, accounts and paths the response
layer refuses to touch.

### prevent

```text
plasma prevent status
plasma prevent applocker [--mode audit|enforce] [--allow-path P]... [--apply --plan ID --reason TEXT]
plasma prevent egress --allow IP[:PORT]... [--apply --plan ID --reason TEXT]
plasma prevent asr --ids GUID[,GUID] [--action Audit|Enabled|Disabled] [--apply --plan ID --reason TEXT]
plasma prevent lsa [--off] [--apply --plan ID --reason TEXT]
plasma prevent rollback --id ID [--apply]
```

Tier 1 prevention through Windows enforcement points. Every control is
dry-run first, plan-gated, verified, journaled and undoable by id.
AppLocker defaults to audit; egress requires an explicit allowlist; ASR needs
Defender; LSA takes effect after a reboot.

### update

```text
plasma update check [--repo OWNER/NAME] [--token-env VAR]
plasma update apply [--bin PATH] [--root PATH] [--allow-unsigned]
```

Anonymous against the public repo; signature-pinned.

### control (agent trust layer)

```text
plasma control policy show|set
plasma control approvals list|approve|deny
plasma control audit tail|verify
plasma control killswitch status|on|off
plasma control tenants list|add|remove
```

`policy set` accepts `--autonomy assist|supervised|autonomous`, `--deny`,
`--allow`, `--max-actions`, `--max-hosts` and `--allow-critical`.
`audit verify` exits 2 if the hash chain is broken. Approvals are single-use
and bound to the tool and argument hash.

### mcp

```text
plasma mcp serve [--root PATH]
```

MCP over stdio. Eleven typed tools; mutating tools return a dry-run plan and
approval reference, never an execution. See
[Agent-native operation](agent-native.md).

### serve

```text
plasma serve [--host 0.0.0.0] [--port 9999] [--api-key KEY]
             [--api-key-file FILE] [--root PATH] [--read-only]
             [--tls-cert FILE --tls-key FILE] [--timeout SECONDS]
             [--max-body BYTES] [--max-output BYTES] [--no-audit] [--quiet]
```

The full CLI over an authenticated HTTP API. `POST /v1/exec` takes an argv
list and runs it through the real parser; `GET /v1/commands` returns the
command tree. The default key is `plasmaplasma`; use `--api-key-file` or
`PLASMA_SERVE_API_KEY` in production. `--read-only` refuses every mutating
command. Every call is written to `<root>/serve/audit.jsonl`. See
[HTTP API](serve.md).

### evidence

```text
plasma evidence export [--framework cbn ndpa pci iso27001] [--out FILE]
```

Writes a JSON control matrix and a Markdown companion.

### assurance

```text
plasma assurance sbom [--out FILE]
plasma assurance safety-case [--out FILE]
plasma assurance support-bundle [--out FILE]
plasma assurance notices
```

## Deployment rings

```text
plasma ring status
plasma ring assign HOST [--ring canary]
plasma ring promote RING
plasma rollback [--bin PATH]
```

### manifest / bundle

```text
plasma manifest verify <path>
plasma bundle create   [--out FILE]
```

Integrity tooling for the embedded payload.

## Common environment variables

| Variable | Used by |
|---|---|
| `PLASMA_GITHUB_TOKEN` | optional token for private forks |
| `PLASMA_SIGNER_THUMBPRINTS` | override the pinned update signers |
| `PLASMA_TG_TOKEN` | Telegram alert token (via `notify.json` `token_env`) |
| `WS1PW`, `WS2PW`, … | fleet inventory `password_env` values |
