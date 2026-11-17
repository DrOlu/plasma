# HTTP API (`plasma serve`)

`plasma serve` exposes the **entire Plasma CLI** over an authenticated HTTP
API. It is an alternative transport to WinRM or SSH: a jumphost, dashboard
or automation calls one endpoint with an argv list, and the host runs the
same command it would run locally.

It is not a general shell. The argv is parsed by the real CLI parser before
anything runs, every command runs in a child process with a hard timeout,
and `--read-only` refuses every command that changes state.

## Quick start

```powershell
plasma serve --port 9999 --api-key-file C:\ProgramData\Plasma\serve.key
```

The default bind is `0.0.0.0:9999`. The default key is `plasmaplasma` for
lab use; production should use `--api-key-file` or
`PLASMA_SERVE_API_KEY`.

```bash
curl -s http://HOST:9999/healthz
curl -s -H "Authorization: Bearer plasmaplasma" \
  http://HOST:9999/v1/version
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | no | liveness only |
| `GET` | `/openapi.json` | no | OpenAPI 3.1 description |
| `GET` | `/docs` | no | human-readable API docs |
| `GET` | `/v1/version` | yes | version, Python, platform, read-only flag |
| `GET` | `/v1/commands` | yes | the full CLI command tree with options |
| `POST` | `/v1/exec` | yes | run one CLI argv |

## OpenAPI

The server publishes an **OpenAPI 3.1** document at `GET /openapi.json`
(no auth) and a self-contained HTML reference at `GET /docs` (no auth).
The spec covers the four API routes, both auth schemes (`bearerAuth` and
`apiKeyAuth`), the request/response envelopes and the error responses.

```bash
curl -s http://HOST:9999/openapi.json | jq '.info'
curl -s http://HOST:9999/openapi.json | jq '.paths | keys'
```

`POST /v1/exec` is deliberately generic: the spec describes the argv
envelope, while the full command surface is discoverable at
`GET /v1/commands` (128 paths with options, mutating flags and
long-running markers). A per-command OpenAPI schema would duplicate the
argparse tree and drift; the command tree is the better contract.

The spec is generated from `plasma/openapi.py` and its `info.version`
tracks the package version. A unit test asserts that the spec paths and
the server routes do not drift apart.

### `POST /v1/exec`

```json
{"argv": ["health", "--root", "C:\\ProgramData\\Plasma"]}
```

or the equivalent:

```json
{"command": "health", "args": ["--root", "C:\\ProgramData\\Plasma"]}
```

The response is the command's exit code plus its captured output:

```json
{
  "ok": true,
  "exit_code": 0,
  "command": "health",
  "argv": ["health"],
  "stdout": "{ ... }",
  "stderr": "",
  "result": { "...": "parsed JSON when stdout is JSON" },
  "truncated": false,
  "duration_ms": 412.7
}
```

`ok` is `true` only when the command exited `0`. A command that ran and
returned a non-zero exit code is still an HTTP `200`; inspect `exit_code`.
HTTP `4xx` means the request was refused before the command ran.

## Authentication

Send either header:

```http
Authorization: Bearer <key>
X-API-Key: <key>
```

The key is compared in constant time. It is never written to the audit log;
only a 12-character SHA-256 prefix is recorded.

Resolution order:

1. `--api-key`
2. `PLASMA_SERVE_API_KEY`
3. `--api-key-file` (first non-empty line)
4. `plasmaplasma`

## Read-only mode

```powershell
plasma serve --read-only
```

Every command that changes host or Plasma state is refused with HTTP `403`
and `code: "read_only"`. This includes any `--apply`, `install`, `update
apply`, `control policy set`, `control killswitch on/off`, `prevent *`,
`actuate apply/undo`, `playbook apply/undo`, `fleet pull/scan`, `store
rotate/compact/redact`, `identity pull/schedule`, `trace run`, `tap run`,
`whids push/ensure/prune`, `canary deploy`, `fim baseline`, `notify test`,
`eval run`, `drift record`, `evidence export`, `assurance sbom`, and the
ring/rollback commands.

Read-only commands such as `health`, `status`, `coverage`, `chain score`,
`actuate actions`, `control policy show`, `control approvals list`,
`control audit verify`, `fleet` reports, `trace list`, `tap list` and
`observe` remain available.

## TLS

```powershell
plasma serve --tls-cert C:\ProgramData\Plasma\serve.crt `
             --tls-key  C:\ProgramData\Plasma\serve.key
```

Both are required together. Use an internal CA certificate; do not expose
the port to the public internet.

## Audit

Every call is appended to `<root>/serve/audit.jsonl`:

```json
{"ts":"2026-11-17T12:00:00Z","remote":"10.0.0.5","key_id":"a1b2c3d4e5f6",
 "argv":["health"],"command":"health","exit_code":0,"duration_ms":412.7,
 "outcome":"ok","read_only":false}
```

The audit log never contains the API key or the command's stdout/stderr.
Disable it with `--no-audit` only if another audit path covers the host.

## Limits

| Limit | Default | Flag |
|---|---|---|
| Request body | 1 MiB | `--max-body` |
| stdout/stderr per call | 8 MiB | `--max-output` |
| Command timeout | 300 s | `--timeout` |
| argv items | 64 | fixed |
| argv item length | 4096 chars | fixed |

Long-running commands (`serve`, `mcp serve`, `watch loop`, `_bridge`) are
refused with HTTP `400` and `code: "long_running"`; run them from the CLI.

## Firewall and cloud security group

On Windows:

```powershell
New-NetFirewallRule -DisplayName "Plasma Serve 9999" `
  -Direction Inbound -Protocol TCP -LocalPort 9999 -Action Allow `
  -Profile Domain,Private
```

In AWS, add an inbound rule to the instance security group for TCP `9999`
from the jumphost or management subnet only. Do not open it to `0.0.0.0/0`.

## When to use it

Use `plasma serve` when:

- WinRM is disabled or blocked by policy;
- you want one transport for Windows and Linux hosts;
- a dashboard or automation needs a typed, auditable command surface;
- you want a read-only observer endpoint.

Prefer WinRM/SSM when:

- the host is already managed by those channels;
- you need Kerberos, JEA or gMSA;
- you do not want another listening service.

`plasma serve` is a narrow API, not a general remote shell. It does not
replace WinRM for interactive administration, and it does not accept
arbitrary commands outside the Plasma CLI.
