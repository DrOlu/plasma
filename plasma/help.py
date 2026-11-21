# ruff: noqa: ISC004
"""Comprehensive, agent-oriented help for the Plasma CLI.

The argparse tree is the source of truth for *syntax*.  This module adds the
part an orchestrating agent needs and argparse cannot infer: what a command
is for, when to use it, what it writes, whether it is safe to run unattended,
and working examples.

Two entry points matter:

* ``plasma <command> --help`` gets a detailed description and examples;
* ``plasma help --json`` returns the whole catalog as one JSON document.

The registry is deliberately explicit.  A test walks the real parser and
fails if a command is added without an entry here.
"""

from __future__ import annotations

import argparse
from typing import Any

from . import __version__

READ_ONLY = "read-only (no host changes)"
LOCAL_WRITE = "writes local Plasma state under --root"
HOST_WRITE = "changes Windows configuration / host state"
PLAN_GATED = "plan-gated and reversible; requires --apply --plan"
NETWORK = "network access"
PRIVILEGED = "requires Administrator or SYSTEM"

EXIT_CODES = {
    "0": "success or clean result",
    "1": "data, input or collection error",
    "2": "refused, drift/findings present, or attention needed",
    "3": "execution, verification or installation failure",
}

COMMON_CONVENTIONS = [
    "Every command prints JSON on stdout except a few human reports "
    "(fleet report). Diagnostics go to stderr where practical.",
    "--root selects the Plasma state root. On Windows the default is "
    "C:\\ProgramData\\Plasma; other platforms use the embedded/bundle root "
    "or the current directory as documented by the command.",
    "--events selects the JSONL event store. Collection commands append to "
    "it; read-only scoring commands never modify it.",
    "Mutating response commands are dry-run by default. They return a plan "
    "id; apply a reviewed plan with --apply --plan <id>.",
    "The kill switch blocks mutating commands while still allowing reads. "
    "Check it before an autonomous run: plasma control killswitch status.",
    "Use plasma help --json to discover commands, arguments, examples and "
    "safety metadata without scraping human help text.",
]

ENVIRONMENT = [
    {"name": "PLASMA_SERVE_API_KEY", "used_by": "serve",
     "meaning": "Bearer key for the HTTP API when --api-key is omitted."},
    {"name": "PLASMA_GITHUB_TOKEN", "used_by": "update",
     "meaning": "Optional token for private release repositories."},
    {"name": "PLASMA_SIGNER_THUMBPRINTS", "used_by": "update",
     "meaning": "Comma-separated Authenticode thumbprints allowed for updates."},
    {"name": "PLASMA_TG_TOKEN", "used_by": "notify",
     "meaning": "Telegram bot token named by notify.json token_env."},
]

GROUPS = [
    ("start", "Start here", [
        "help", "status", "health", "manifest", "bundle", "probe", "ask",
        "install", "serve", "mcp", "eval",
    ]),
    ("collect", "Collection and detection", [
        "whids", "identity", "tap", "trace", "sigma", "canary", "memory", "fim",
        "deep", "observe", "chain", "coverage", "store", "watch", "notify",
        "query", "tree", "summarize", "detect",
    ]),
    ("respond", "Response and prevention", [
        "actuate", "playbook", "enforce", "protect", "prevent", "intercept",
    ]),
    ("fleet", "Fleet and case work", ["fleet", "case", "drift"]),
    ("trust", "Agent trust, audit and evidence", [
        "control", "evidence", "assurance",
    ]),
    ("deploy", "Updates and deployment", ["update", "ring", "rollback"]),
]


def _c(summary: str, description: str, examples: list[tuple[str, str]],
       safety: str = READ_ONLY, notes: list[str] | None = None,
       output: str | None = None, see_also: list[str] | None = None,
       hidden: bool = False) -> dict:
    return {
        "summary": summary,
        "description": description.strip(),
        "examples": examples,
        "safety": safety,
        "notes": notes or [],
        "output": output or "JSON on stdout.",
        "see_also": see_also or [],
        "hidden": hidden,
    }


COMMANDS: dict[str, dict] = {}


def _add(path: str, spec: dict) -> None:
    COMMANDS[path] = spec


# ---------------------------------------------------------------------------
# Start here
# ---------------------------------------------------------------------------

_add("help", _c(
    "detailed command reference with examples and a machine-readable catalog",
    """Show the agent-oriented command reference.

With no topic, `plasma help` prints the command map, the agent workflow,
exit codes and conventions. With a topic, it prints the same detailed help
as `plasma <topic> --help`. With --json it returns the complete catalog:
every command path, summary, description, arguments, defaults, choices,
examples, safety class and related commands.

Use this first when orchestrating Plasma. It is designed so an agent does
not have to guess command names or flags.""",
    [
        ("Overview and workflow", "plasma help"),
        ("One command in depth", "plasma help control approvals approve"),
        ("Machine-readable catalog", "plasma help --json"),
        ("Catalog for one command", "plasma help prevent asr --json"),
    ],
    notes=["`plasma help --json` is stable JSON: parse it instead of "
           "scraping the text help.",
           "Exit 1 means the requested topic does not exist."],
    output="Human text by default; one JSON object with --json.",
    see_also=["status", "health", "serve"],
))

_add("status", _c(
    "verify the bundle and report its probe menu and coverage",
    """Report what this Plasma payload contains: manifest verification,
product and schema version, installed sensors, probe names and a compact
capability summary. It is the cheapest way to answer "is this node the
build I think it is?" before running detection or response commands.""",
    [
        ("Current bundle", "plasma status"),
        ("A specific bundle directory", "plasma status --bundle D:\\Plasma\\bundle"),
        ("Include an event store in the summary", "plasma status --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
    ],
    notes=["Read-only. Does not install, start or change sensors."],
    see_also=["health", "manifest", "coverage"],
))

_add("health", _c(
    "deterministic health verdict for the local Plasma stack",
    """Run the health checks that catch the failures seen in the field:
missing or hung sensors, a stopped WHIDS service, a dead tap, an
unreadable event store, and a stale configuration. The result is one JSON
verdict with per-check detail, not a stream of speculative warnings.

`health` is the first command to run on a host that is reporting nothing.""",
    [
        ("Default root", "plasma health"),
        ("Explicit root", "plasma health --root D:\\Plasma"),
    ],
    notes=["Exit 1 when a required check fails; inspect checks[].ok and "
           "checks[].detail.",
           "Use `watch once` for health plus drift, alerts and chains."],
    see_also=["watch", "whids", "tap"],
))

_add("manifest", _c(
    "create or verify the SHA-256 manifest for a bundle",
    """The manifest is the integrity contract for a deployed bundle. `create`
walks --dir, records the SHA-256 and size of every file, and writes the
manifest. `verify` recomputes the hashes, checks the schema version and
reports missing, extra or modified files.

Use `verify` before trusting a copied bundle or after moving it between
hosts. The installer verifies the embedded manifest automatically.""",
    [
        ("Build a manifest", "plasma manifest create --dir .\\bundle --version 1.19.0"),
        ("Verify a bundle", "plasma manifest verify --dir .\\bundle"),
    ],
    notes=["`create` writes <dir>/manifest.json. `verify` exits 3 when an "
           "artifact is missing or its hash differs."],
    see_also=["bundle", "status", "install"],
))

_add("bundle build", _c(
    "build the deployable bundle directory and manifest",
    """Assemble the embedded instance, sensors, documentation and optional
engine binaries into --out. The manifest is written last. `--platform` and
`--binary` are repeatable; `--no-zip` skips archive creation.""",
    [
        ("Default", "plasma bundle build"),
        ("Custom engines and binary", "plasma bundle build --out dist --engines .\\engines --platform windows-x86_64 --binary .\\plasma.exe --no-zip"),
    ],
    safety=LOCAL_WRITE,
    see_also=["bundle", "manifest"],
))

_add("bundle", _c(
    "build the deployable bundle (manifest, payload, docs, optional engines)",
    """Assemble an immutable deployment directory from the embedded
instance, sensor declarations, documentation and optional platform engine
binaries. The manifest is written last so the bundle travels with its own
integrity record.

Most operators consume a released Windows executable instead of building
a bundle. This command is for packaging a custom payload or a new sensor
set.""",
    [
        ("Default build", "plasma bundle build"),
        ("Custom output and engines", "plasma bundle build --out dist --engines .\\engines --platform windows-x86_64"),
        ("Include a specific executable", "plasma bundle build --binary .\\dist\\plasma.exe --no-zip"),
    ],
    safety=LOCAL_WRITE,
    notes=["`--platform` and `--binary` are repeatable.",
           "`--no-zip` leaves the directory loose instead of producing an archive."],
    see_also=["manifest", "install"],
))

_add("probe", _c(
    "execute one named frozen probe and print its structured answer",
    """Run a single probe from the embedded bundle by name. This is the
deterministic path: the caller chooses the probe, Plasma executes the
reviewed payload and returns JSON. It is suitable when the orchestrator
already knows which question to ask.

Use `status` to list probe names, or `ask` to let the on-device model choose.""",
    [
        ("List probes first", "plasma status"),
        ("Run a probe with no arguments", "plasma probe --tool attest --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Pass probe arguments as JSON", "plasma probe --tool canary --args '{\"names\":[\"plasma-canary\"]}'"),
    ],
    notes=["`--args` must be a JSON object.",
           "Refusals are structured JSON with an error field; the command "
           "does not invent an answer."],
    see_also=["ask", "status", "observe"],
))

_add("ask", _c(
    "let the on-device model choose a probe and execute it",
    """Natural-language front door to the frozen probe menu. The local model
selects one probe from the reviewed set, Plasma executes it, and the
structured answer is returned. The model chooses *which* question to ask;
it cannot author or modify a payload.

Prefer `probe` in automation where determinism matters. Use `ask` for
exploration and analyst-style questions.""",
    [
        ("Ask about persistence", "plasma ask --prompt \"what persistence exists on this host?\" --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Choose an explicit engine", "plasma ask --prompt \"show logon edges\" --engine embedded"),
    ],
    notes=["No network model is required by default; the embedded engine "
           "and weights are used.",
           "If the model cannot choose a valid probe, Plasma returns a "
           "structured refusal instead of a guess."],
    see_also=["probe", "status", "observe"],
))

_add("install", _c(
    "install or repair the Plasma payload on this Windows host",
    """Intelligent installer. It verifies the embedded manifest, decides
FULL versus MINIMAL based on what the host can actually run, provisions
Sysmon and WHIDS when feasible, writes the configuration and ACLs, flips
the current junction, and registers the SYSTEM tasks:

* PlasmaWatch - measured enforcement sweep every 5 minutes;
* PlasmaWhidsWatchdog - heal a hung WHIDS every 2 minutes;
* PlasmaIdentityPull - Security-channel collection every 15 minutes;
* PlasmaUpdate - signed self-update once a day.

Re-running with --force is the supported repair path. Existing policy,
approvals, ledgers and event stores are preserved where possible.

`--dry-run` plans without changing the host. `--skip-whids` forces MINIMAL.
`--require-whids` fails closed when the full stack is not feasible.
`--no-autoprotect` installs the old dry-run-only posture.
`--no-autoupdate` removes the daily update task.

`--rotate` is used by the MSI custom action: after staging the version it
swaps `bin\\plasma.exe` and restarts the registered tasks so the running node
immediately reports the package version. The same rotation happens
automatically at the end of `update apply`.""",
    [
        ("Plan an install", "plasma install --dry-run"),
        ("Default install", "plasma install"),
        ("Repair an existing install", "plasma install --force --root C:\\ProgramData\\Plasma"),
        ("Minimal install without WHIDS/Sysmon", "plasma install --skip-whids"),
        ("Install with automatic containment off", "plasma install --no-autoprotect"),
    ],
    safety=HOST_WRITE + "; " + PRIVILEGED,
    notes=["Run from an elevated PowerShell or as SYSTEM.",
           "The installer is idempotent. --force repairs files and tasks "
           "without deleting case data.",
           "A custom --root must be writable only by SYSTEM and Administrators."],
    see_also=["status", "health", "protect", "update"],
))

_add("serve", _c(
    "run the authenticated HTTP API for the full CLI",
    """Expose every CLI command over HTTP so a jumphost, dashboard or agent
can administer the host without WinRM or SSH.

Routes:
  GET  /healthz        liveness and version (no auth)
  GET  /v1/version     version, runtime and command count
  GET  /v1/commands    the command tree as JSON
  POST /v1/exec        {"argv": ["health"]} - runs the real parser

Authentication is a bearer key. The default bind is 127.0.0.1:9999. A
non-loopback bind refuses the known default key (plasmaplasma) unless
--allow-insecure-default-key is passed; use --api-key-file or
PLASMA_SERVE_API_KEY. --read-only refuses mutating commands. Every call is appended to <root>/serve/audit.jsonl
unless --no-audit is set.

Use TLS (--tls-cert/--tls-key) whenever the listener is not on loopback.""",
    [
        ("Local listener", "plasma serve --host 127.0.0.1 --port 9999"),
        ("Key from a file", "plasma serve --host 0.0.0.0 --port 9999 --api-key-file C:\\ProgramData\\Plasma\\serve.key"),
        ("Read-only API", "plasma serve --read-only"),
        ("TLS", "plasma serve --tls-cert server.crt --tls-key server.key --api-key-file serve.key"),
        ("Call it", "curl -H \"Authorization: Bearer plasmaplasma\" -H \"Content-Type: application/json\" -d '{\"argv\":[\"health\"]}' http://127.0.0.1:9999/v1/exec"),
    ],
    safety=NETWORK + "; " + PRIVILEGED,
    notes=["The API runs the same allowlisted parser as the CLI; it cannot "
           "invent commands.",
           "Register it as a SYSTEM task if it must survive logoff. The lab "
           "estate uses the PlasmaServe task.",
           "Never expose the default key on a routable interface."],
    see_also=["help", "mcp", "control"],
))

_add("mcp", _c(
    "serve Plasma's typed tools over MCP stdio",
    """Start the harness-agnostic Model Context Protocol server. The harness
lists the typed tools, calls one, and receives a schema-validated result
or a structured refusal / approval request. Policy, kill switch and the
provenance ledger are enforced inside Plasma, not in the model.

MCP is the right integration for an agent runtime that speaks MCP. Use
`serve` for plain HTTP automation.""",
    [
        ("Start MCP on stdio", "plasma mcp serve"),
        ("Explicit root", "plasma mcp serve --root C:\\ProgramData\\Plasma"),
    ],
    safety=LOCAL_WRITE,
    notes=["Mutating tools return a dry-run plan and approval reference; "
           "they do not execute on the first call.",
           "The transport is stdio; do not add logging to stdout."],
    see_also=["serve", "control", "actuate"],
))

_add("mcp serve", _c(
    "run the MCP server over stdio",
    """Start the JSON-RPC MCP server and expose Plasma's typed tools to the
harness. Mutating tools return a plan and approval reference; they do not
execute on the first call. Policy, kill switch and the ledger are enforced
inside Plasma.""",
    [
        ("Default root", "plasma mcp serve"),
        ("Explicit root", "plasma mcp serve --root D:\\Plasma"),
    ],
    safety=LOCAL_WRITE,
    notes=["The transport is stdio. Keep stdout free of diagnostics."],
    see_also=["mcp", "serve", "control"],
))

_add("eval run", _c(
    "run the behavioural safety eval suite",
    """Execute the deterministic policy, kill-switch, approval, rate-limit
and blast-radius tests. The result reports passed/failed counts and the
names of failing cases. These evals never perform destructive actions.""",
    [
        ("Run", "plasma eval run"),
        ("Custom root", "plasma eval run --root D:\\Plasma"),
    ],
    safety=LOCAL_WRITE,
    notes=["Exit 2 when any eval fails.",
           "Run after changing policy or before raising autonomy."],
    see_also=["eval", "control policy", "control"],
))

_add("eval", _c(
    "run the behavioural safety evals for the agent policy layer",
    """Exercise the policy, kill switch, approval binding, rate limits and
blast-radius checks with a deterministic harness. These are safety tests,
not detection tests. Run them after changing policy or before raising the
autonomy tier.

The result reports passed/failed counts and the failing case names.""",
    [
        ("Run evals", "plasma eval run"),
        ("Run against a custom root", "plasma eval run --root D:\\Plasma"),
    ],
    notes=["Exit 2 when any eval fails.",
           "The evals never perform destructive actions; they assert that "
           "the policy refuses them."],
    see_also=["control", "actuate"],
))

# ---------------------------------------------------------------------------
# Collection and detection
# ---------------------------------------------------------------------------

_add("whids", _c(
    "WHIDS sensor control: alerts, IOC push, diagnostics and repair",
    """Operate the bundled WHIDS HIDS. Pull normalized alerts from the WHIDS
database into Plasma's event store, push Plasma's IOC gene file back to
WHIDS, inspect sensor/service state, diagnose a broken install, heal a hung
service, or prune old WHIDS data.

WHIDS is detect-only in Plasma. Dump hooks are disabled and dump trees are
not part of the install.""",
    [
        ("Pull alerts", "plasma whids pull --root \"C:\\Program Files\\Whids\" --out C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Inspect coverage", "plasma whids status --root \"C:\\Program Files\\Whids\" --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Heal the service", "plasma whids ensure --root \"C:\\Program Files\\Whids\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["health", "watch", "identity"],
))

_add("whids pull", _c(
    "pull WHIDS alerts into Plasma's normalized event store",
    """Read new WHIDS alerts, normalize them to PlasmaEvent rows, redact
credential-bearing command lines and append them to the event store. The
pull is bounded and deduplicated by event identity.

Run it before chain scoring, watch, or fleet correlation if WHIDS is the
primary sensor on this host.""",
    [
        ("Default paths", "plasma whids pull --root \"C:\\Program Files\\Whids\" --out C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Label the host", "plasma whids pull --root \"C:\\Program Files\\Whids\" --out events.jsonl --host WS1"),
    ],
    safety=LOCAL_WRITE,
    notes=["The installer registers a WHIDS watchdog, but alert pulling is "
           "part of the periodic sweep or an explicit call."],
    see_also=["whids", "chain", "watch"],
))

_add("whids push", _c(
    "push Plasma indicators to WHIDS as a gene/IOC file (dry-run by default)",
    """Turn Plasma's own indicators into WHIDS gene rules and show or apply
the generated file. Dry-run is the default: inspect the diff first, then
repeat with --apply to replace plasma-iocs.gen atomically.

Confidence is on the gene 0-10 scale. The maximum indicator count bounds
the blast radius of a bad feed.""",
    [
        ("Preview indicators", "plasma whids push --root \"C:\\Program Files\\Whids\" --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Apply with high confidence", "plasma whids push --root \"C:\\Program Files\\Whids\" --events events.jsonl --min-confidence 9 --max-indicators 500 --apply --reason \"confirmed campaign\""),
        ("Restart WHIDS after apply", "plasma whids push ... --apply --restart-service"),
    ],
    safety=HOST_WRITE + "; " + PLAN_GATED,
    notes=["Only indicators at or above --min-confidence are written.",
           "--restart-service asks Windows to restart WHIDS after the file swap."],
    see_also=["whids", "control", "actuate"],
))

_add("whids status", _c(
    "report WHIDS service state, rule coverage and integration health",
    """Combine the Windows service state, the installed rule/gene files and
the event store to answer whether WHIDS is actually contributing detections.
A running service with no rules or an unreadable store is reported as
degraded, not healthy.""",
    [
        ("Default WHIDS root", "plasma whids status --root \"C:\\Program Files\\Whids\" --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
    ],
    see_also=["health", "whids diagnose", "coverage"],
))

_add("whids diagnose", _c(
    "collect a bounded WHIDS diagnostic report",
    """Inspect the WHIDS install, configuration, service, log tail and rule
files, and return a compact diagnostic object. Use it when `whids status`
shows a problem or the service will not start / hangs in StartPending.""",
    [
        ("Diagnose", "plasma whids diagnose"),
        ("Custom install", "plasma whids diagnose --root D:\\Whids"),
    ],
    notes=["Read-only. Does not restart or rewrite anything."],
    see_also=["whids ensure", "health"],
))

_add("whids ensure", _c(
    "heal a stopped or hung WHIDS service",
    """The watchdog body. Running is a no-op. A service stuck in
StartPending is force-stopped and restarted. A stopped service is started.
Actions are appended to logs/whids-watchdog.log.

The installer registers PlasmaWhidsWatchdog to run this every two minutes
as SYSTEM, so manual use is mainly for immediate repair.""",
    [
        ("Heal now", "plasma whids ensure"),
        ("Wait for a slow start", "plasma whids ensure --root \"C:\\Program Files\\Whids\" --wait 60"),
    ],
    safety=HOST_WRITE + "; " + PRIVILEGED,
    see_also=["whids diagnose", "health"],
))

_add("whids prune", _c(
    "prune old WHIDS data within explicit size and age bounds",
    """Delete old WHIDS database/log data according to --max-mb and
--keep-days. Dry-run is the default; --dry-run makes the plan explicit.
The command never deletes outside the WHIDS install directory.""",
    [
        ("Preview", "plasma whids prune --install-dir \"C:\\Program Files\\Whids\" --max-mb 500 --keep-days 30 --dry-run"),
        ("Apply", "plasma whids prune --install-dir \"C:\\Program Files\\Whids\" --max-mb 500 --keep-days 30"),
    ],
    safety=HOST_WRITE,
    notes=["Pruning is irreversible. Run with --dry-run first and confirm "
           "the reported paths."],
    see_also=["whids status", "store"],
))

_add("identity", _c(
    "Security-channel audit collection and scheduling",
    """Read Windows Security events that are not re-emitted to realtime ETW:
logon success/failure, Kerberos, NTLM and process creation (4688 when
audited). Events are UTC-normalized, deduplicated and bounded, then appended
to the Plasma event store.

The installer registers PlasmaIdentityPull every 15 minutes as SYSTEM.""",
    [
        ("Pull now", "plasma identity pull --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Check the task", "plasma identity schedule-status"),
        ("Change the interval", "plasma identity schedule --every 10"),
    ],
    safety=LOCAL_WRITE,
    see_also=["whids", "watch", "fleet"],
))

_add("identity pull", _c(
    "pull a bounded set of Security-channel events into the store",
    """Read the Security channel through the Event Log API. The default IDs
cover logon, Kerberos, NTLM and process creation. `--ids` is allowlisted:
anything outside the supported set is rejected before PowerShell runs.

`--max-events` bounds the pull (default 2000) and `--since` bounds the time
window in minutes. The collector deduplicates against the tail of the store.""",
    [
        ("Default pull", "plasma identity pull --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Last 30 minutes, 500 events", "plasma identity pull --events events.jsonl --since 30 --max-events 500"),
        ("Only logon events", "plasma identity pull --events events.jsonl --ids 4624,4625,4776"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    notes=["4688 requires the process-creation audit policy; a zero count "
           "is reported honestly, not hidden.",
           "Kerberos KDC events are normally zero on a member server."],
    see_also=["identity schedule", "fleet"],
))

_add("identity schedule", _c(
    "register or update the periodic Security-channel pull task",
    """Create or replace the SYSTEM task that runs `identity pull` on an
interval. The task uses the current executable and the selected root.
Changes take effect on the next scheduled run.""",
    [
        ("Every 15 minutes", "plasma identity schedule --every 15"),
        ("Bind to a specific executable", "plasma identity schedule --every 5 --exe C:\\ProgramData\\Plasma\\bin\\plasma.exe"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    see_also=["identity schedule-status", "identity unschedule"],
))

_add("identity unschedule", _c(
    "remove the periodic Security-channel pull task",
    """Unregister the identity-pull scheduled task. Existing events in the
store are untouched. Use this during maintenance or when collection is
managed by another tool.""",
    [("Remove the task", "plasma identity unschedule")],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    see_also=["identity schedule", "identity schedule-status"],
))

_add("identity schedule-status", _c(
    "show whether the identity-pull task exists and when it last ran",
    """Report the task name, state, last run time and last result. Use it
after install or scheduling to confirm collection is actually configured.""",
    [("Inspect", "plasma identity schedule-status")],
    see_also=["identity schedule", "health"],
))

_add("tap", _c(
    "ETW tap control: providers, selftest, bounded live windows",
    """The C++ tap (krabsetw) streams high-value ETW providers, scores in
memory and emits matches only. These commands list providers, verify the
tap binary/rules, run a bounded live window, and normalize captured matches
into the event store.""",
    [
        ("List providers", "plasma tap list"),
        ("Verify the tap", "plasma tap selftest"),
        ("Run for 30 seconds", "plasma tap run --for 30s --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
    ],
    safety=LOCAL_WRITE,
    see_also=["trace", "health", "coverage"],
))

_add("tap list", _c(
    "list the ETW providers the tap can subscribe to",
    """Print the reviewed provider allowlist with the event areas each one
covers. This is the menu used by `tap run --providers`.""",
    [("List", "plasma tap list")],
    see_also=["tap run", "tap selftest"],
))

_add("tap selftest", _c(
    "verify the tap executable, rules and session prerequisites",
    """Run a bounded self-test: confirm the tap binary exists and starts,
the rule file parses, and the required ETW session can be created. Exit 3
means the session could not start.""",
    [
        ("Default payload", "plasma tap selftest"),
        ("Explicit binary and rules", "plasma tap selftest --tap-exe .\\sensors\\tap\\plasma-tap.exe --rules .\\sensors\\tap\\rules.json"),
    ],
    notes=["Read-only with respect to host configuration; it opens and "
           "closes an ETW session."],
    see_also=["tap run", "health"],
))

_add("tap run", _c(
    "run a bounded live ETW window and write matches",
    """Start the tap for a fixed duration, subscribe to the selected
providers, and emit only rule matches. Optionally normalize the matches
into the Plasma event store. The window is always bounded: there is no
unattended infinite capture.

`--max-matches` and `--for` are the safety limits. Exit 3 means the ETW
session could not start.""",
    [
        ("Short explicit window", "plasma tap run --for 30s"),
        ("Specific providers and store", "plasma tap run --providers Microsoft-Windows-Sysmon,Microsoft-Windows-Security-Auditing --for 60s --events events.jsonl"),
        ("Keep raw matches", "plasma tap run --for 30s --out-dir .\\tap-out --max-matches 5000"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    notes=["--providers takes a comma-separated list from `tap list`.",
           "The tap requires Administrator; the installer provisions it."],
    see_also=["tap list", "tap collect", "trace"],
))

_add("tap collect", _c(
    "normalize a saved tap match file into the event store",
    """Import matches produced by an earlier `tap run` or copied from
another host. Each match is normalized to the PlasmaEvent schema, redacted
and deduplicated before append. Use this for offline analysis or when
collection and analysis happen on different machines.""",
    [
        ("Import matches", "plasma tap collect --matches .\\tap-out\\matches.jsonl --events events.jsonl"),
        ("Label the source host", "plasma tap collect --matches matches.jsonl --events events.jsonl --host WS1"),
    ],
    safety=LOCAL_WRITE,
    see_also=["tap run", "store", "chain"],
))

_add("trace", _c(
    "DTrace on-demand kernel tracing",
    """Use Microsoft DTrace as a microscope for a bounded window. Plasma
ships reviewed scripts, checks the local install, can provision DTrace,
and normalizes trace rows into the event store. This is on-demand depth,
not a permanent sensor.""",
    [
        ("List scripts", "plasma trace list"),
        ("Check readiness", "plasma trace check"),
        ("Run a script", "plasma trace run net-events.d --events events.jsonl --for 5s"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    see_also=["trace provision", "tap", "health"],
))

_add("trace list", _c(
    "list the reviewed DTrace scripts shipped with Plasma",
    """Print each script's name, purpose and the fields it emits. Scripts
use `tid` for estate portability and are bounded by the runner.""",
    [("List scripts", "plasma trace list")],
    see_also=["trace run", "trace check"],
))

_add("trace check", _c(
    "check whether DTrace is installed, enabled and ready",
    """Report the DTrace version and whether the Windows DTrace feature is
enabled. A host that is installed but not enabled is reported explicitly;
Plasma does not silently assume it works.""",
    [("Check", "plasma trace check")],
    see_also=["trace provision", "trace run"],
))

_add("trace selftest", _c(
    "run a minimal DTrace selftest",
    """Execute a tiny known script and verify that rows arrive with the
expected shape. Use it after provisioning or when a real trace returns
nothing.""",
    [("Selftest", "plasma trace selftest")],
    notes=["Requires DTrace to be installed and enabled."],
    see_also=["trace check", "trace provision"],
))

_add("trace run", _c(
    "run one reviewed DTrace script for a bounded window",
    """Run a script from the reviewed set, enforce a duration and row cap,
normalize the output and optionally append it to the event store. The
script is chosen from the shipped set; arbitrary local paths are refused.

`--for` accepts durations such as 5s or 2m. `--max-rows` prevents a noisy
trace from filling the store.""",
    [
        ("Five-second trace", "plasma trace run net-events.d --events events.jsonl --for 5s"),
        ("Cap rows and save raw output", "plasma trace run proc-events.d --events events.jsonl --for 10s --max-rows 10000 --out trace.raw.jsonl"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    see_also=["trace list", "trace check"],
))

_add("trace provision", _c(
    "install and enable Microsoft DTrace",
    """Install the DTrace package (direct MSI when winget is absent), enable
it with bcdedit, and report whether a reboot is required. Installed and
enabled is the ready state; Plasma does not chase versions.

This is a host change. Review the plan first when operating under change
control.""",
    [("Provision", "plasma trace provision")],
    safety=HOST_WRITE + "; " + PRIVILEGED,
    notes=["Usually reports reboot_required: true. Run `trace check` after "
           "the reboot."],
    see_also=["trace check", "trace selftest"],
))

_add("sigma", _c(
    "convert Sigma rules into WHIDS gene rules",
    """Convert a Sigma rule file or directory into Plasma's gene schema.
Selections become field matches, the condition is preserved where possible,
and unsupported constructs are reported as skipped rather than silently
mistranslated.

Writing is the default; --dry-run previews the conversion and writes
nothing. A write produces a gene file plus a summary of converted and
skipped rules.""",
    [
        ("Preview conversion (writes nothing)", "plasma sigma convert --in .\\sigma\\ --dry-run"),
        ("Write the gene file", "plasma sigma convert --in .\\sigma\\ --out .\\sensors\\whids\\plasma-sigma.gen"),
    ],
    safety=LOCAL_WRITE,
    notes=["Check `skipped` and the reasons; a high skip count means the "
           "corpus needs review.",
           "Test converted rules with `whids status` and a controlled "
           "trigger before relying on them."],
    see_also=["whids", "coverage"],
))

_add("sigma convert", _c(
    "convert Sigma rules into WHIDS gene rules",
    """Read a Sigma file or directory, translate supported selections and
conditions into the gene schema, and report skipped rules with reasons.
Writing is the default; `--dry-run` previews and writes nothing. A write
produces the gene file and a summary of converted and skipped rules.""",
    [
        ("Preview", "plasma sigma convert --in .\\sigma\\ --dry-run"),
        ("Write the gene file", "plasma sigma convert --in .\\sigma\\ --out .\\sensors\\whids\\plasma-sigma.gen"),
    ],
    safety=LOCAL_WRITE,
    notes=["Review skipped rules before deploying the generated file.",
           "Test converted rules with a controlled trigger."],
    see_also=["sigma", "whids", "coverage"],
))

_add("canary", _c(
    "decoy files, registry keys, DNS/HTTP tokens and an active shield",
    """Canaries answer the questions heuristics answer late: did something
enumerate and destroy user documents, and did something use an artifact
that no legitimate workflow should touch?

File canaries are hash-verified decoys. DNS tokens are unique hostnames
whose queries are observed through a narrow Sysmon EID 22 include. HTTP
tokens are `.url` shortcuts served by a local Plasma collector. Registry
keys are decoys watched by the shield. File and registry canaries can be
wrapped by the active shield, which kills a process that creates, deletes or
registry-writes them after verifying the live PID and image.

All passive hits produce the same `source="canary"` alert rows in the event
store, so `watch`, `fleet` and the response policy see one evidence path.
The shield adds a narrow active response; it is not a kernel driver and reads
do not trigger it.""",
    [
        ("Deploy believable file decoys", "plasma canary deploy --dir D:\\Shares\\Finance"),
        ("Create a DNS token", "plasma canary token create --kind dns --domain assets.internal"),
        ("Create an HTTP token", "plasma canary token create --kind http --base-url http://collector:8088"),
        ("Start the local collector", "plasma canary serve --host 127.0.0.1 --port 8088"),
        ("Create a registry canary", "plasma canary registry deploy --hive HKCU --count 1"),
        ("Create a pipe canary", "plasma canary pipe deploy --count 1"),
        ("Preview the active shield", "plasma canary shield install"),
    ],
    safety=LOCAL_WRITE,
    see_also=["fim", "watch", "canary shield", "canary registry", "canary pipe", "canary token"],
))

_add("canary deploy", _c(
    "create realistic canary files and record their hashes",
    """Write decoy documents to the configured locations (or explicit
directories) and record each path, size and SHA-256 in the manifest.
Existing canaries are left untouched; their current hash is recorded, not
overwritten.

By default each location gets a plausible subdirectory and a random subset
of document names. The content is a valid document body and never says
"canary". Use --no-randomize when an external policy pins exact paths.""",
    [
        ("Default randomized layout", "plasma canary deploy"),
        ("A real user-data directory", "plasma canary deploy --dir D:\\Shares\\Finance"),
        ("Fixed names for a lab", "plasma canary deploy --no-randomize"),
    ],
    safety=LOCAL_WRITE,
    see_also=["canary verify", "canary status"],
))

_add("canary verify", _c(
    "check canary files for modification or deletion",
    """Recompute each canary hash and compare it with the manifest. Missing,
modified or replaced files are reported as findings. Exit 2 means at least
one canary was touched.""",
    [("Verify all", "plasma canary verify")],
    see_also=["canary deploy", "watch"],
))

_add("canary status", _c(
    "summarize the canary manifest and last verification",
    """List the deployed canaries, their locations and the last known state.
Use it to confirm coverage before an incident rather than discovering a
missing decoy during one.""",
    [("Status", "plasma canary status")],
    see_also=["canary deploy", "canary verify"],
))

_add("canary token", _c(
    "create and manage native DNS and HTTP canary tokens",
    """A token is a unique artifact that should never be used. DNS tokens are
observed from Sysmon EID 22 (or any event carrying `dns_query`) and need no
callback service. HTTP tokens point at `plasma canary serve` and are
delivered as Windows `.url` shortcuts. Both write a local registry under
the Plasma root; no cloud service is involved.""",
    [
        ("DNS token", "plasma canary token create --kind dns --domain assets.internal"),
        ("HTTP token", "plasma canary token create --kind http --base-url http://collector:8088"),
        ("List tokens", "plasma canary token list"),
    ],
    safety=LOCAL_WRITE,
    notes=["Token ids are unguessable but not secrets: anyone who can read "
           "the registry can enumerate them. Protect the Plasma root.",
           "DNS tokens need a narrow Sysmon DnsQuery include: run "
           "`plasma canary sysmon --apply` after creating them."],
    see_also=["canary serve", "canary collect", "canary sysmon"],
))

_add("canary token create", _c(
    "create a DNS hostname token or an HTTP URL token",
    """Allocate a unique 96-bit token id and write the registry entry.

For `--kind dns`, --domain is the suffix (for example assets.internal);
the token is `<id>.<domain>`. Optionally write the FQDN to --out.

For `--kind http`, --base-url is the collector (for example
http://collector:8088); the token URL is `<base>/t/<id>`. A Windows `.url`
artifact is written to --out or `<root>/canary-artifacts/`.""",
    [
        ("DNS token for an internal suffix", "plasma canary token create --kind dns --domain assets.internal"),
        ("HTTP token with a plausible shortcut name", "plasma canary token create --kind http --base-url http://collector:8088 --name Intranet_Portal.url"),
        ("Write a DNS token artifact", "plasma canary token create --kind dns --domain assets.internal --out C:\\Shares\\Finance\\notes.txt"),
    ],
    safety=LOCAL_WRITE,
    notes=["The artifact contains no secret; its value is that it should "
           "never be opened or resolved.",
           "A DNS token needs a matching internal DNS record (usually a "
           "wildcard/sinkhole for the suffix) and `plasma canary sysmon "
           "--apply`.",
           "HTTP base URLs must be http(s), must not contain credentials, "
           "and must not include a path."],
    see_also=["canary token list", "canary sysmon", "canary serve"],
))

_add("canary token list", _c(
    "list registered canary tokens",
    """Print every token id, kind, artifact path and creation time. Use it to
confirm what was deployed and to get the id for removal.""",
    [("List", "plasma canary token list")],
    see_also=["canary token create", "canary token remove"],
))

_add("canary token remove", _c(
    "remove a token from the local registry",
    """Remove one token by id. The artifact is left in place unless
--delete-artifact is set, and even then deletion is restricted to paths
under the Plasma root.""",
    [
        ("Remove", "plasma canary token remove 0123456789abcdef01234567"),
        ("Remove and delete its artifact", "plasma canary token remove 0123456789abcdef01234567 --delete-artifact"),
    ],
    safety=LOCAL_WRITE,
    see_also=["canary token list", "canary collect"],
))

_add("canary serve", _c(
    "run the local HTTP token collector",
    """Bind a small HTTP listener that recognizes `/t/<token-id>` and records
the hit. It returns a 1x1 GIF, never serves files, accepts only GET/HEAD,
and refuses a non-loopback bind unless --allow-non-loopback is explicit.
This is a local collector, not a public web service.""",
    [
        ("Loopback collector", "plasma canary serve --host 127.0.0.1 --port 8088"),
        ("Collector VLAN interface", "plasma canary serve --host 10.0.5.20 --allow-non-loopback"),
        ("Stop after one hit for a test", "plasma canary serve --max-requests 1"),
    ],
    safety=LOCAL_WRITE + "; long-running",
    notes=["Hits are written to <root>/canary-hits.jsonl. `watch` or "
           "`canary collect` turns them into event-store alerts.",
           "Use a management VLAN or a dedicated collector host; do not "
           "expose this port to the internet."],
    see_also=["canary token create", "canary collect", "canary hits"],
))

_add("canary collect", _c(
    "collect DNS and HTTP token hits into the event store",
    """Pull a bounded Sysmon DNS window, scan the existing event-store tail,
and ingest new local HTTP hits. Only matching token queries or known token
ids become `source="canary"` alert rows. Collection is idempotent: a hit
key is recorded so repeated sweeps do not duplicate alerts.""",
    [
        ("Collect now", "plasma canary collect"),
        ("Short DNS window", "plasma canary collect --since 5 --max-events 200"),
        ("Explicit store", "plasma canary collect --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
    ],
    safety=LOCAL_WRITE,
    notes=["Sysmon DNS collection requires Windows and a DnsQuery include; "
           "see `plasma canary sysmon`."],
    see_also=["canary sysmon", "canary hits", "watch"],
))

_add("canary hits", _c(
    "show recent canary alert rows from the event store",
    """Print the tail of `source="canary"` alerts. This is the quick check
after a controlled test or during triage; it does not modify the store.""",
    [
        ("Recent hits", "plasma canary hits"),
        ("Last 10", "plasma canary hits --last 10"),
    ],
    see_also=["canary collect", "watch", "chain"],
))

_add("canary sysmon", _c(
    "write or apply a narrow Sysmon DnsQuery include for token domains",
    """Generate the Plasma Sysmon baseline with an include rule for the
registered DNS token suffixes, then optionally hot-reload it through
Sysmon64.exe -c. Only queries ending in a token suffix are logged; ordinary
DNS traffic stays out of the channel.

Without --apply the command only writes
`<root>/tools/plasma-sysmon-baseline.xml`.""",
    [
        ("Write from registered tokens", "plasma canary sysmon"),
        ("Write and apply", "plasma canary sysmon --apply"),
        ("Explicit suffix", "plasma canary sysmon --domain assets.internal --apply"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    notes=["--apply requires Administrator and an installed Sysmon service.",
           "--apply replaces the Sysmon config with Plasma's baseline plus "
           "the token include; review an existing custom config first.",
           "The include is suffix-based; a token hostname must end with one "
           "of the configured domains."],
    see_also=["canary token create", "canary collect", "watch"],
))

_add("intercept", _c(
    "deterministic policy at native interception points",
    """Interception is the layer between a sensor and a responder: it sees an
attempt at the boundary and can allow, deny, or record a would-be denial.
Plasma does not ship a kernel driver. It brokers typed rules into gates
Windows already owns: NTFS ACLs for canary files, Windows Firewall for
outbound destinations, and the MCP boundary for agent tool calls.

Phase 0 is shadow evaluation over the event store. Phase 1 is canary ACL
protection. Phase 2 is the agent tool-call gateway. Phase 3 applies rules
with a dry-run, plan id, journal, verification and rollback.""",
    [
        ("Status", "plasma intercept status"),
        ("Shadow-evaluate rules", "plasma intercept evaluate --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Protect canaries", "plasma intercept protect-canary"),
        ("Apply a rule", "plasma intercept apply block-test-net --apply --plan 12 --reason \"IR-42\""),
    ],
    safety=LOCAL_WRITE + "; " + PLAN_GATED,
    notes=["Rules are typed and deterministic; the model may propose but "
           "cannot apply one without the plan gate.",
           "No kernel driver and no arbitrary shell: backends are ACL, "
           "firewall and the agent gateway."],
    see_also=["prevent", "canary", "mcp", "watch"],
))

_add("intercept status", _c(
    "show intercept rules, enforcement mode and journal counts",
    """Read the local rule registry and journal summary. Use it before an
incident to confirm which rules exist and whether they are shadow or
enforcing.""",
    [("Status", "plasma intercept status")],
    see_also=["intercept rules list", "intercept evaluate"],
))

_add("intercept rules", _c(
    "manage the local intercept rule registry",
    """Rules live in `<root>/intercept-rules.json`. A rule has an id, a point,
a match object, an action, a backend and a mode. Rules are validated before
they are written; unknown fields and malformed values are refused.""",
    [
        ("List rules", "plasma intercept rules list"),
        ("Add from a file", "plasma intercept rules add --file rules.json"),
    ],
    safety=LOCAL_WRITE,
    see_also=["intercept rules add", "intercept apply"],
))

_add("intercept rules list", _c(
    "list intercept rules",
    """Print every rule id, point, action, backend, mode and match. This is
read-only and safe on a read-only HTTP API.""",
    [("List", "plasma intercept rules list")],
    see_also=["intercept rules add", "intercept rules remove"],
))

_add("intercept rules add", _c(
    "add one or more rules from a JSON file",
    """The file may contain one rule object or `{"rules": [...]}`. Every rule
is validated and the registry is written atomically. Existing rule ids are
refused rather than replaced.""",
    [
        ("Add one rule", "plasma intercept rules add --file rule.json"),
        ("Add a set", "plasma intercept rules add --file rules.json"),
    ],
    safety=LOCAL_WRITE,
    see_also=["intercept rules list", "intercept rules remove"],
))

_add("intercept rules remove", _c(
    "remove an intercept rule",
    """Remove one rule by id. Removing a rule does not undo an already-applied
native policy; use `intercept rollback --id <journal-id>` for that.""",
    [("Remove", "plasma intercept rules remove block-test-net")],
    safety=LOCAL_WRITE,
    see_also=["intercept rules list", "intercept rollback"],
))

_add("intercept evaluate", _c(
    "shadow-evaluate rules over the event store",
    """Read a bounded tail of the event store and apply every matching rule.
This is Phase 0: it records `would_block` decisions without changing a host.
Use it to tune rules before enforcement, or to explain what an enforcing
rule would have done. Exit 0 even when would-block decisions exist; the
JSON reports the count.

`--out` writes the decisions to a file, which is a local write; without it
the command is read-only.""",
    [
        ("Evaluate", "plasma intercept evaluate --events events.jsonl"),
        ("Bounded tail", "plasma intercept evaluate --max-rows 1000"),
        ("Write decisions", "plasma intercept evaluate --out decisions.json"),
    ],
    safety=LOCAL_WRITE,
    see_also=["intercept rules list", "watch", "chain"],
))

_add("intercept apply", _c(
    "apply a native intercept rule (dry-run by default)",
    """Compile one rule to its native backend and render the exact payload.
Without `--apply` the command journals a dry-run and returns a plan id.
With `--apply --plan <id>` it claims that plan, changes the native policy,
verifies the result and writes an undo recipe.

Supported enforcing backends: `acl` (canary file protection) and `firewall`
(outbound destination block). `gateway` rules apply at the MCP boundary and
need no host mutation. AppLocker and ASR remain available through
`plasma prevent` with the same plan discipline.""",
    [
        ("Dry-run a firewall rule", "plasma intercept apply block-test-net"),
        ("Apply it", "plasma intercept apply block-test-net --apply --plan 12 --reason \"IR-42\""),
        ("Dry-run a canary ACL rule", "plasma intercept apply protect-canary"),
    ],
    safety=LOCAL_WRITE + "; " + PLAN_GATED + "; " + PRIVILEGED,
    notes=["A bad inline policy can break a host. Default is dry-run; the "
           "plan is single-use and payload-bound.",
           "ACL apply stores the prior SDDL for rollback."],
    see_also=["intercept rollback", "prevent", "intercept protect-canary"],
))

_add("intercept protect-canary", _c(
    "protect canary files with an NTFS deny/audit ACL",
    """Read the canary manifest, add a deny ACE for write/delete by Everyone
and a failure audit rule, then verify the ACL. The canary becomes both a
tripwire and a small safe: a destructive writer is denied and the attempt is
recorded. The prior SDDL is journaled for rollback.

Without `--apply` this is a dry-run; with `--apply --plan <id>` it applies
the reviewed plan. The Sysmon/file audit policy must be enabled for failure
events to reach the Security log.""",
    [
        ("Dry-run", "plasma intercept protect-canary"),
        ("Apply", "plasma intercept protect-canary --apply --plan 7 --reason \"canary protection\""),
        ("Only a prefix", "plasma intercept protect-canary --prefix D:\\Finance"),
    ],
    safety=LOCAL_WRITE + "; " + PLAN_GATED + "; " + PRIVILEGED,
    notes=["A deny ACE is enforced by NTFS, not a Plasma driver.",
           "Rollback restores the exact prior SDDL captured at apply time."],
    see_also=["canary deploy", "intercept rollback", "watch"],
))

_add("intercept rollback", _c(
    "undo an applied intercept action by journal id",
    """Find an applied ACL or firewall entry, render its undo payload, and
require a second dry-run plan. ACL rollback restores the saved SDDL;
firewall rollback removes the named rule. The kill switch blocks rollback
execution, but a dry-run remains available.""",
    [
        ("Dry-run rollback", "plasma intercept rollback --id 4"),
        ("Apply rollback", "plasma intercept rollback --id 4 --apply --plan 9 --reason \"test complete\""),
    ],
    safety=LOCAL_WRITE + "; " + PLAN_GATED + "; " + PRIVILEGED,
    see_also=["intercept apply", "intercept protect-canary", "intercept status"],
))

_add("memory", _c(
    "bounded on-demand process-memory scanning",
    """Memory is the layer Sysmon, WHIDS and file integrity cannot see. Plasma
binds HollowsHunter (PE-sieve) as an explicit probe that looks inside a
running process for hollowed or replaced PEs, reflective DLLs, shellcode,
inline hooks and in-memory patches.

The scanner is pinned and SHA-256 verified. It runs only when asked, writes
a bounded scan archive under `<root>/memory/`, and appends normalized
findings as `source="memory"` alerts. No dumps are produced by default.""",
    [
        ("Scan one PID", "plasma memory scan --pid 4832"),
        ("Scan by name", "plasma memory scan --pname powershell.exe,rundll32.exe"),
        ("Deep scan", "plasma memory scan --pid 4832 --deep"),
        ("Tool status", "plasma memory status"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    notes=["`--all` scans every process and can be slow; prefer a PID or name.",
           "`--dump` writes potentially sensitive process artifacts under the "
           "Plasma root and is refused with --all.",
           "The scanner is user-mode and cannot see every protected process."],
    see_also=["watch", "enforce", "intercept", "trace"],
))

_add("memory scan", _c(
    "scan targeted processes with the pinned HollowsHunter scanner",
    """Run HollowsHunter against a PID list, process-name list, or all
processes. The default scan adds shellcode-pattern detection; `--deep` adds
thread-stack scanning. Reports are archived locally; findings become
`source="memory"` alert rows, deduplicated across repeated scans.

Exit 0 means clean, 2 means findings, 1 means an input/tool error.""",
    [
        ("One process", "plasma memory scan --pid 4832"),
        ("A small name set", "plasma memory scan --pname powershell.exe,rundll32.exe --deep"),
        ("All processes", "plasma memory scan --all --timeout 120"),
        ("Scan and dump artifacts", "plasma memory scan --pid 4832 --dump"),
    ],
    safety=LOCAL_WRITE + "; " + PRIVILEGED,
    notes=["No raw dumps by default; --dump is explicit and local.",
           "The scanner is hash-pinned; a mismatched binary is refused.",
           "A clean scan is a point-in-time result, not proof of innocence."],
    see_also=["memory status", "watch", "enforce", "intercept"],
))

_add("memory status", _c(
    "show scanner availability, hashes and last scan",
    """Report the resolved 64/32-bit scanner, its SHA-256, the pinned version
and the most recent scan metadata. Read-only.""",
    [("Status", "plasma memory status")],
    see_also=["memory scan", "memory list"],
))

_add("memory list", _c(
    "list recent memory scans",
    """Print the archived scan metadata, including targets, elapsed time,
suspicious count and report directory. Read-only.""",
    [("Recent scans", "plasma memory list")],
    see_also=["memory scan", "memory status"],
))

_add("fim", _c(
    "critical-file integrity monitoring",
    """Record and verify SHA-256, size and metadata for critical files and
directories. FIM answers the compliance question "did a critical file
change?", while canaries answer the impact question "was a decoy
destroyed?".

Baselines live under the Plasma root and are explicit, so a change is
reported against a known snapshot rather than an opaque vendor baseline.""",
    [
        ("Baseline defaults", "plasma fim baseline"),
        ("Baseline one path", "plasma fim baseline --path C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ("Verify", "plasma fim verify"),
    ],
    safety=LOCAL_WRITE,
    see_also=["canary", "watch", "health"],
))

_add("fim baseline", _c(
    "record hashes for the FIM watch set",
    """Walk the configured paths (or one explicit --path) and store path,
SHA-256, size and timestamps as the baseline. Existing baselines are
replaced atomically. Run this after a known-good change window.""",
    [
        ("Default watch set", "plasma fim baseline"),
        ("One path", "plasma fim baseline --path C:\\ProgramData\\Plasma\\config.json"),
    ],
    safety=LOCAL_WRITE,
    notes=["A baseline taken after compromise records the compromise. Take "
           "it from a known-good state."],
    see_also=["fim verify", "fim status"],
))

_add("fim verify", _c(
    "compare the current files with the FIM baseline",
    """Recompute hashes and report added, removed, modified and unreadable
files. Exit 2 means drift was found. The result is structured so an agent
can decide whether the change is expected.""",
    [("Verify", "plasma fim verify")],
    see_also=["fim baseline", "watch"],
))

_add("fim status", _c(
    "show the baseline coverage and age",
    """Report which paths are covered, when the baseline was taken and
whether any baseline entries are missing. Use it to detect silent loss of
coverage before trusting a clean verify.""",
    [("Status", "plasma fim status")],
    see_also=["fim baseline", "fim verify"],
))

_add("deep", _c(
    "deep persistence inspection across every auto-start location",
    """One bounded pass over registry run keys, services and service DLLs,
scheduled task actions, IFEO debugger hijacks, Winlogon shell/userinit and
WMI event subscriptions, with Authenticode status for each executable.

This is broader than an event-driven rule: it sees what is present now,
including persistence that predates the sensor.""",
    [
        ("Scan", "plasma deep persistence"),
        ("Save the raw result", "plasma deep persistence --json-out persistence.json --cap 500"),
    ],
    safety=READ_ONLY,
    see_also=["observe attackmap", "chain", "watch"],
))

_add("deep persistence", _c(
    "scan every persistence auto-start location now",
    """Collect all supported auto-start locations and return entries with
path, command line, signer status and source. `--cap` bounds the number of
rows so a pathological host cannot exhaust memory.

Use `observe attackmap` for the named-question view; use this command when
you want the raw, complete inventory.""",
    [
        ("Default cap", "plasma deep persistence"),
        ("Save and cap", "plasma deep persistence --json-out .\\persistence.json --cap 1000"),
    ],
    safety=READ_ONLY,
    notes=["Requires PowerShell 5.1+; the payload reads registry, service, "
           "task and WMI state."],
    see_also=["observe", "chain"],
))

_add("observe", _c(
    "run one named local observatory question",
    """Answer a fixed read-only question about the host using a reviewed
PowerShell payload. The questions cover identity surface, logon and
network edges, PowerShell logs, persistence attack maps, registry edges,
flow statistics, canary state and Sysmon health.

`observe` is the deterministic, named-question interface. `probe` runs the
frozen neuralOS probe menu; `ask` lets the model pick a probe.""",
    [
        ("Identity attestation", "plasma observe attest"),
        ("Persistence map", "plasma observe attackmap"),
        ("Logon edges", "plasma observe edges"),
        ("Custom canary names", "plasma observe canary --canary finance-decoy,hr-decoy"),
    ],
    notes=["Every question is read-only and locally executed.",
           "Unknown questions return the valid list in the error object."],
    see_also=["probe", "ask", "deep", "drift"],
))

_add("chain", _c(
    "score ordered multi-step attack stories in the event store",
    """A single finding says something happened. A chain says this happened,
then this, then this. Chain scoring matches ordered step sequences within a
time window and returns a story-level score, not another isolated alert.

Use it after collection and before watch/fleet reporting.""",
    [
        ("Score the store", "plasma chain score --events C:\\ProgramData\\Plasma\\data\\events.jsonl"),
        ("Wider window", "plasma chain score --events events.jsonl --window 900"),
    ],
    notes=["Exit 2 means at least one chain matched.",
           "The store is read-only; scoring never appends."],
    see_also=["watch", "coverage", "fleet"],
))

_add("chain score", _c(
    "score ordered chains over a bounded tail of the event store",
    """Scan up to --max-rows recent events, match the shipped chain
definitions, and return each matched chain with its steps, hosts and score.
`--window` is the maximum gap between adjacent steps in seconds.""",
    [
        ("Default window", "plasma chain score --events events.jsonl"),
        ("Bounded scan", "plasma chain score --events events.jsonl --max-rows 50000 --window 600"),
    ],
    see_also=["chain", "watch"],
))

_add("coverage", _c(
    "report ATT&CK coverage and blind spots from the shipped rule sets",
    """Read the tap rules, gene baseline and IOC feed, extract the ATT&CK
technique IDs they actually cover, and diff that against the full matrix.
The result includes covered techniques and explicit blind spots.

Coverage is about what the rules watch, not what the host happened to
emit. Use it to prioritize rule work rather than to claim completeness.""",
    [
        ("Default sensors", "plasma coverage"),
        ("Custom sensor directory", "plasma coverage --sensors .\\sensors"),
    ],
    see_also=["status", "chain", "deep"],
))

_add("store", _c(
    "event-store hygiene: rotate, compact, redact and inspect",
    """Keep the JSONL event diary bounded and safe. Rotation archives the
live file by size, compaction removes exact duplicates, redaction removes
credential-bearing command lines, and stats reports size and shape.

These commands operate on a file, not a service. Use them during
maintenance or before exporting evidence.""",
    [
        ("Stats", "plasma store stats --events events.jsonl"),
        ("Rotate", "plasma store rotate --events events.jsonl --max-mb 50 --keep 3"),
        ("Compact", "plasma store compact --events events.jsonl --out events.dedup.jsonl"),
        ("Redact", "plasma store redact --events events.jsonl --out events.redacted.jsonl"),
    ],
    safety=LOCAL_WRITE,
    see_also=["chain", "fleet", "evidence"],
))

_add("store rotate", _c(
    "rotate the live event file into numbered archives",
    """Rename the live file to .1, shift .k to .k+1, and drop the oldest
beyond --keep. No-op below --max-mb. This is the standard way to keep the
diary from growing without bound while preserving a recent tail and a few
archives.""",
    [
        ("50 MB, three archives", "plasma store rotate --events events.jsonl --max-mb 50 --keep 3"),
    ],
    see_also=["store compact", "store stats"],
))

_add("store compact", _c(
    "remove exact duplicate events into a new file",
    """Deduplicate by the event identity while preserving first-seen order.
The source file is not modified; the compacted output is written to --out.
Use it before handing a store to an auditor or another tool.""",
    [
        ("Compact to a new file", "plasma store compact --events events.jsonl --out events.dedup.jsonl"),
    ],
    see_also=["store rotate", "store redact"],
))

_add("store redact", _c(
    "redact credentials from command lines in the store",
    """Find command lines that carry passwords or tokens and replace the
secret portion while preserving the surrounding command. The output is a
new file; the original is untouched. Redaction is conservative and reports
how many rows changed.""",
    [
        ("Redact", "plasma store redact --events events.jsonl --out events.redacted.jsonl"),
    ],
    notes=["Always inspect the redaction summary and a sample before "
           "sharing a store outside the estate."],
    see_also=["store compact", "evidence"],
))

_add("store stats", _c(
    "summarize event-store size, row count and time range",
    """Report file size, event count, first/last timestamps, event kinds and
the largest sources. This is the quick check before rotation or when a
store looks unexpectedly small.""",
    [("Stats", "plasma store stats --events events.jsonl")],
    see_also=["store rotate", "health"],
))

_add("watch", _c(
    "one sweep or a loop: health, drift, canaries, alerts, chains and enforcement",
    """The periodic decision sweep. `watch once` combines health, drift,
canary files, DNS/HTTP token hits, configured canary accounts, new alerts
and chain scoring into one verdict, optionally delivering notifications and
feeding the measured enforcement policy. `watch loop` repeats on an interval
for foreground operation.

Exit is non-zero when findings exist, which makes the command suitable for
a scheduled task or an orchestrator check.""",
    [
        ("One sweep", "plasma watch once"),
        ("One sweep with enforcement", "plasma watch once --enforce"),
        ("Query a canary account", "plasma watch once --canary-account svc-print-archive"),
        ("Loop every 60 seconds", "plasma watch loop --every 60 --enforce"),
    ],
    safety=LOCAL_WRITE,
    see_also=["health", "enforce", "notify", "canary"],
))

_add("watch once", _c(
    "run one full detection and decision sweep",
    """Collect the current state, compare against baselines, score new
chains, and return a verdict. With --enforce, findings are passed to the
measured enforcement policy, which still applies its own allowlist, score
floor, action cap and cooldown.

Canary accounts come from `canary.accounts` in config.json unless
--canary-account overrides them. DNS and HTTP token hits are collected
automatically and deduplicated across sweeps.

`--notify-clean` sends a notification even when nothing is found; the
default is to notify only on findings.""",
    [
        ("Detect only", "plasma watch once"),
        ("Measured enforcement", "plasma watch once --enforce"),
        ("Query a specific canary account", "plasma watch once --canary-account svc-print-archive"),
        ("Notify even when clean", "plasma watch once --notify-clean"),
    ],
    safety=LOCAL_WRITE,
    notes=["The installer runs `watch once --enforce` via PlasmaWatch every "
           "5 minutes.",
           "A finding does not automatically mean an action: the policy "
           "decides."],
    see_also=["enforce", "protect", "notify", "canary"],
))

_add("watch loop", _c(
    "repeat watch sweeps in the foreground",
    """Run `watch once` every --every seconds until interrupted. Intended
for a console or a process supervisor; the installed SYSTEM task uses the
single-shot form instead.""",
    [
        ("Every 60 seconds", "plasma watch loop --every 60"),
        ("Every 5 minutes with enforcement", "plasma watch loop --every 300 --enforce"),
    ],
    safety=LOCAL_WRITE,
    see_also=["watch once", "health"],
))

_add("notify", _c(
    "inspect and test alert-delivery channels",
    """Notification channels are configured in <root>/notify.json. Secrets
are never stored there; a channel names an environment variable via
token_env. `notify show` renders the effective configuration with secrets
redacted. `notify test` sends a test message.

Delivery is best-effort: a broken channel must never block detection or
containment.""",
    [
        ("Show channels", "plasma notify show"),
        ("Send a test", "plasma notify test"),
    ],
    safety=LOCAL_WRITE,
    see_also=["watch", "control"],
))

_add("notify show", _c(
    "show configured notification channels with secrets redacted",
    """List each channel, its type, target, minimum score and whether its
token environment variable is present. Secrets are never printed.""",
    [("Show", "plasma notify show")],
    see_also=["notify test"],
))

_add("notify test", _c(
    "send a test notification through every configured channel",
    """Send a clearly labelled test message and report per-channel success
or failure. Use it after configuring a channel and before relying on it
during an incident.""",
    [
        ("Test all", "plasma notify test"),
        ("Label the source host", "plasma notify test --host WS1"),
    ],
    safety=NETWORK,
    see_also=["notify show", "watch"],
))

# ---------------------------------------------------------------------------
# Response and prevention
# ---------------------------------------------------------------------------

_add("actuate", _c(
    "scoped, journaled, reversible response actions",
    """The response engine. Every action is allowlisted, target-validated,
protected-object aware and journaled before execution. A dry-run mints a
single-use plan bound to the action and target; execution requires that
plan. Undo restores the prior state where the action is reversible.

Protected services, processes, accounts and paths (WinRM, RDP, WHIDS,
Sysmon, LSASS, SYSTEM, Administrator, Plasma itself) are refused even when
a caller asks directly.""",
    [
        ("List actions", "plasma actuate actions"),
        ("Plan a kill", "plasma actuate apply kill_process --target 4242 --reason \"confirmed beacon\""),
        ("Apply the reviewed plan", "plasma actuate apply kill_process --target 4242 --reason \"confirmed beacon\" --apply --plan <id>"),
        ("Undo", "plasma actuate undo --id <applied-id> --apply --plan <undo-plan>"),
    ],
    safety=PLAN_GATED,
    see_also=["playbook", "enforce", "protect"],
))

_add("actuate actions", _c(
    "list the response actions, risk tiers and reversibility",
    """Print the allowlist as JSON: action name, what it changes, its risk
tier, whether it is reversible and which scope it targets. This is the
machine-readable menu an orchestrator should use instead of guessing.""",
    [("List", "plasma actuate actions")],
    see_also=["actuate apply", "playbook list"],
))

_add("actuate apply", _c(
    "plan or apply one response action",
    """Dry-run by default: validate the action and target, refuse protected
objects, and return a plan id plus an expiry. Repeat the identical command
with --apply --plan <id> to execute it. Applying without a matching seen
plan is refused.

Actions: block_ip, delete_task, disable_task, disable_user,
disable_wmi_sub, isolate_host, kill_process, quarantine_file, remove_admin,
remove_run_key, rotate_credential, snapshot, stop_service.

Targets vary by action: PID, user, IP, path, service, task or host. The
command validates the target before minting the plan.""",
    [
        ("Plan a process kill", "plasma actuate apply kill_process --target 4242 --reason \"confirmed beacon\""),
        ("Apply the plan", "plasma actuate apply kill_process --target 4242 --reason \"confirmed beacon\" --apply --plan 42"),
        ("Plan host isolation", "plasma actuate apply isolate_host --target WS1 --reason \"confirmed lateral movement\""),
        ("Snapshot before a change", "plasma actuate apply snapshot --target C:\\Users\\bob\\Documents --reason \"preserve evidence\""),
    ],
    safety=PLAN_GATED,
    notes=["The plan is single-use and bound to the action and target.",
           "Isolation and destructive actions are never applied by the "
           "measured automatic policy without approval.",
           "Check `plasma control killswitch status` first in autonomous runs."],
    see_also=["actuate undo", "actuate journal", "playbook"],
))

_add("actuate journal", _c(
    "read the response journal",
    """Return the append-only record of plans, applies, refusals and undos,
newest first. Each row includes the action, target, reason, plan id,
operator/agent identity and result. Use it to reconstruct what happened
without relying on console history.""",
    [
        ("Recent entries", "plasma actuate journal --last 20"),
    ],
    see_also=["actuate apply", "control audit"],
))

_add("actuate undo", _c(
    "plan or apply the undo for an executed action",
    """Mint an undo plan for a journaled action, then apply it with the same
--apply --plan pair. Not every action is reversible; the action metadata
says so and undo returns a structured refusal when it cannot restore
state.""",
    [
        ("Plan an undo", "plasma actuate undo --id 42"),
        ("Apply it", "plasma actuate undo --id 42 --apply --plan <id>"),
    ],
    safety=PLAN_GATED,
    see_also=["actuate apply", "actuate journal"],
))

_add("playbook", _c(
    "named, reviewed sequences of response actions",
    """A playbook is a fixed sequence of existing allowlisted actions,
applied as one plan-gated unit. It is a bigger allowlist, not a wider door:
each step is still individually validated and journaled, and the sequence
stops at the first failure.

Two reviewed playbooks ship: contain-user and isolate-box.""",
    [
        ("List playbooks", "plasma playbook list"),
        ("Plan containment", "plasma playbook apply contain-user --target bob --reason \"credential theft\""),
    ],
    safety=PLAN_GATED,
    see_also=["actuate", "enforce"],
))

_add("playbook list", _c(
    "list playbooks and their steps",
    """Print each playbook name, purpose and ordered steps with the action
and target scope for every step. Use it to choose a reviewed sequence
instead of composing ad-hoc actions.""",
    [("List", "plasma playbook list")],
    see_also=["playbook apply", "actuate actions"],
))

_add("playbook apply", _c(
    "plan or apply a named playbook",
    """Dry-run by default. The response is a plan id and the fully expanded
step list. Apply with --apply --plan to execute all steps in order. If a
step fails, the playbook stops and reports `aborted_at`; earlier steps are
not silently rolled back.

`contain-user` disables the account and preserves evidence; `isolate-box`
snapshots then isolates the host.""",
    [
        ("Plan user containment", "plasma playbook apply contain-user --target bob --reason \"confirmed credential theft\""),
        ("Apply the plan", "plasma playbook apply contain-user --target bob --reason \"confirmed credential theft\" --apply --plan <id>"),
        ("Plan host isolation", "plasma playbook apply isolate-box --target WS1 --reason \"ransomware behaviour\""),
    ],
    safety=PLAN_GATED,
    see_also=["playbook list", "playbook undo", "actuate"],
))

_add("playbook undo", _c(
    "undo the reversible steps of a playbook run",
    """Plan or apply the inverse of a playbook execution. Steps that cannot
be reversed are reported individually; the command does not pretend a
non-reversible action was restored.""",
    [
        ("Plan an undo", "plasma playbook undo --id 42"),
        ("Apply it", "plasma playbook undo --id 42 --apply --plan <id>"),
    ],
    safety=PLAN_GATED,
    see_also=["playbook apply", "actuate undo"],
))

_add("enforce", _c(
    "policy-gated automatic response (Tier 0 prevention)",
    """Turn detection findings into a bounded set of proposed actions, then
execute only what policy allows. The shipped posture is armed but narrow:
snapshot and kill_process at score 9+, at most two actions per run, with a
30-minute cooldown. Isolation and every other action require approval.

`PlasmaWatch` runs `watch once --enforce` every five minutes; this command
is for manual runs and inspection.""",
    [
        ("Inspect policy", "plasma enforce status"),
        ("Dry-run", "plasma enforce run --dry-run"),
        ("Apply allowed actions", "plasma enforce run --apply"),
        ("Review pending approvals", "plasma enforce pending"),
    ],
    safety=PLAN_GATED,
    see_also=["protect", "watch", "control approvals"],
))

_add("enforce run", _c(
    "evaluate findings and optionally execute policy-allowed actions",
    """Read the latest findings (or an explicit --findings file), apply the
policy's allowlist, score floor, action cap, cooldown and protected-object
checks, and either propose a plan (default / --dry-run) or execute the
allowed subset (--apply).

The policy decides, not the caller. A high score does not bypass an
approval requirement.""",
    [
        ("Dry-run", "plasma enforce run --dry-run"),
        ("Apply", "plasma enforce run --apply"),
        ("Use a findings file", "plasma enforce run --findings findings.json --dry-run"),
    ],
    safety=PLAN_GATED,
    see_also=["enforce status", "enforce pending", "watch once"],
))

_add("enforce status", _c(
    "show the measured enforcement policy and recent decisions",
    """Report whether enforcement is armed, its mode, score floor, allowed
actions, approval-required actions, cooldown and per-run cap. This is the
quick way to confirm what the host will do without a human in the loop.""",
    [("Status", "plasma enforce status")],
    see_also=["protect status", "enforce run"],
))

_add("enforce pending", _c(
    "list containment decisions waiting for approval",
    """Return pending actions with their finding, score, target, plan id and
expiry. An approver should review the finding before approving. Expired
entries are not executable.""",
    [("Pending", "plasma enforce pending")],
    see_also=["enforce approve", "control approvals"],
))

_add("enforce approve", _c(
    "approve a pending containment decision",
    """Approve one pending action by id. Without --apply the approval is
recorded; with --apply the approved action is executed through the normal
actuate path. The approval is single-use and bound to the stored action.""",
    [
        ("Record approval", "plasma enforce approve --id 17"),
        ("Approve and execute", "plasma enforce approve --id 17 --apply"),
    ],
    safety=PLAN_GATED,
    see_also=["enforce pending", "actuate apply"],
))

_add("protect", _c(
    "measured protection posture: armed, narrow and reversible",
    """Inspect or change the default protection posture. Plasma ships armed
but narrow: automatic containment is limited to snapshot and kill_process
at score 9+, two actions per run and a 30-minute cooldown. Everything else
stays behind approval. `disarm` is a human override that restores dry-run
behaviour without uninstalling detection.

`arm` writes the measured block; `disarm` disables automatic containment
but leaves detection and manual response intact.""",
    [
        ("Status", "plasma protect status"),
        ("Disarm", "plasma protect disarm --reason \"change window\""),
        ("Re-arm", "plasma protect arm --reason \"change complete\""),
        ("Protected objects", "plasma protect protected"),
    ],
    safety=LOCAL_WRITE,
    see_also=["enforce", "watch", "prevent"],
))

_add("protect status", _c(
    "show the effective protection posture",
    """Report detection mode, containment enabled/mode, score floor,
allowed and approval-required actions, cooldown, action cap, watch task and
the kill-switch state. Use this as the authoritative answer to "is this
host actually protected right now?".""",
    [("Status", "plasma protect status")],
    see_also=["enforce status", "protect protected"],
))

_add("protect arm", _c(
    "arm the measured protection posture",
    """Write the ship-default measured enforcement block: snapshot and
kill_process at score 9+, two actions per run, 30-minute cooldown,
approval for everything else. Optionally arm prevention controls as well.

Arming does not grant blanket execution: the policy still checks every
finding and the kill switch still wins.""",
    [
        ("Arm containment", "plasma protect arm --reason \"incident response\""),
        ("Arm prevention too", "plasma protect arm --apply-prevention --reason \"harden after review\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["protect disarm", "enforce run", "prevent"],
))

_add("protect disarm", _c(
    "disable automatic containment while keeping detection",
    """Set the enforcement block to disabled/dry-run. Detection, manual
response, approvals and audit remain available. This is the human override
for a false-positive storm or a change window.""",
    [("Disarm", "plasma protect disarm --reason \"false-positive review\"")],
    safety=LOCAL_WRITE,
    notes=["Disarming is recorded. Re-arm with `protect arm` when the "
           "review is complete."],
    see_also=["protect arm", "enforce status"],
))

_add("protect protected", _c(
    "list the services, processes, accounts and paths response refuses to touch",
    """Print the protected-object contract used by every response command.
These objects are refused even when an operator or agent asks directly:
core Windows processes, LSASS/CSRSS/WINLOGON, WHIDS and Sysmon, WinRM/RDP
services, SYSTEM/Administrator and the Plasma install tree.

Read this before planning a response so a target is not rejected late.""",
    [("List", "plasma protect protected")],
    see_also=["actuate actions", "protect status"],
))

_add("prevent", _c(
    "Tier 1 prevention through signed Windows enforcement points",
    """Apply real inline prevention using Windows' own signed components:
AppLocker for execution, Windows Firewall for egress, Defender ASR for
behaviour, LSA protection for credential access, Controlled Folder Access,
Network Protection and the vulnerable driver blocklist. WDAC is inventoried
read-only because a bad boot-time policy is not safely automated.

Every control is dry-run first, plan-gated, verified after apply, journaled
and reversible by id. Prevention is intentionally separate from detection
so a failed control cannot silently disable detection.""",
    [
        ("Posture and applyability", "plasma prevent posture"),
        ("Plan AppLocker audit mode", "plasma prevent applocker --mode audit"),
        ("Preview Controlled Folder Access", "plasma prevent cfa --mode audit"),
        ("Preview Network Protection", "plasma prevent network --mode audit"),
        ("Preview the driver blocklist", "plasma prevent driver-blocklist"),
        ("Undo a control", "plasma prevent rollback --id 12 --apply --plan <id>"),
    ],
    safety=PLAN_GATED,
    see_also=["protect", "control", "assurance"],
))

_add("prevent status", _c(
    "show the effective prevention controls and their state",
    """Report AppLocker mode, egress applied/allowlist, ASR rule posture and
LSA protection, including which controls are audit-only. A control that is
planned but not applied is reported as such.""",
    [("Status", "plasma prevent status")],
    see_also=["prevent applocker", "prevent egress"],
))

_add("prevent applocker", _c(
    "plan or apply an AppLocker execution policy",
    """Build an AppLocker policy from the allow paths, defaulting to audit
mode so the effect is observable before enforcement. Apply with the plan
id. The policy is verified after apply and journaled for rollback.""",
    [
        ("Audit plan", "plasma prevent applocker --mode audit"),
        ("Enforce with explicit allows", "plasma prevent applocker --mode enforce --allow-path \"C:\\Program Files\\*\" --allow-path \"C:\\Windows\\*\" --apply --plan <id> --reason \"approved baseline\""),
    ],
    safety=PLAN_GATED + "; " + PRIVILEGED,
    notes=["Start in audit mode. Review the audit events before switching "
           "to enforce.",
           "An incorrect enforce policy can block administration tools; "
           "keep an out-of-band recovery path."],
    see_also=["prevent status", "prevent rollback"],
))

_add("prevent egress", _c(
    "plan or apply a default-deny egress firewall allowlist",
    """Create a Windows Firewall outbound policy that blocks by default and
permits only the explicit --allow entries. The allow list is required: an
empty policy is refused because it would cut the host off.

Each allow entry is IP, IP:port, CIDR or a documented host token accepted
by the validator. Apply with the plan id.""",
    [
        ("Plan", "plasma prevent egress --allow 10.0.0.10:443 --allow 10.0.0.11:443"),
        ("Apply", "plasma prevent egress --allow 10.0.0.10:443 --allow 10.0.0.11:443 --apply --plan <id> --reason \"approved egress\""),
    ],
    safety=PLAN_GATED + "; " + NETWORK,
    notes=["An egress policy can break WinRM/RDP/WHIDS. Include every "
           "management path before applying.",
           "Rollback by id restores the prior firewall profile."],
    see_also=["prevent status", "prevent rollback", "health"],
))

_add("prevent asr", _c(
    "plan or apply Defender Attack Surface Reduction rules",
    """Set Defender ASR rules by GUID with an explicit action (Audit,
Enabled/Block, or Disabled). The command validates that Defender is
present before planning; a host without Defender is refused rather than
silently skipped.

Apply with the plan id. Verification reads the effective rule state back.""",
    [
        ("Audit a rule", "plasma prevent asr --ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 --action Audit"),
        ("Block a rule", "plasma prevent asr --ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 --action Enabled --apply --plan <id> --reason \"approved ASR baseline\""),
    ],
    safety=PLAN_GATED + "; " + PRIVILEGED,
    see_also=["prevent status", "prevent rollback"],
))

_add("prevent lsa", _c(
    "plan or apply LSA protection (RunAsPPL)",
    """Enable LSA protection so LSASS runs as a protected process, or
disable it with --disable. The change requires a reboot to take effect;
the result reports `reboot_required`.

Use this only after confirming the host's security baseline and any
third-party LSASS consumers.""",
    [
        ("Plan enable", "plasma prevent lsa"),
        ("Apply enable", "plasma prevent lsa --apply --plan <id> --reason \"approved baseline\""),
        ("Disable", "plasma prevent lsa --disable --apply --plan <id> --reason \"compatibility rollback\""),
    ],
    safety=PLAN_GATED + "; " + PRIVILEGED,
    notes=["Takes effect after reboot. Verify with `prevent status`.",
           "Some endpoint agents are incompatible with RunAsPPL; test in "
           "the ring first."],
    see_also=["prevent status", "protect protected"],
))

_add("prevent rollback", _c(
    "undo a prevention control by journal id",
    """Plan or apply the inverse of a previously applied prevention control.
The journal id identifies the exact change and its prior state; rollback
does not guess. Apply with the undo plan id.""",
    [
        ("Plan rollback", "plasma prevent rollback --id 12"),
        ("Apply rollback", "plasma prevent rollback --id 12 --apply --plan <id>"),
    ],
    safety=PLAN_GATED,
    see_also=["prevent applocker", "prevent egress", "prevent asr"],
))

# ---------------------------------------------------------------------------
# Fleet and case work
# ---------------------------------------------------------------------------

_add("fleet", _c(
    "cross-host correlation from one desk",
    """Pull a capped tail from each host's event store, correlate lateral
hops, shared indicators, canaries and blind hosts, and produce a case
report. Endpoints need no new agent: their normalized JSONL stores are the
interface.

Transports: `file` for a local/shared path, `winrm` for a remote host.
Passwords come from environment variables named by password_env, never
from the inventory file.""",
    [
        ("Pull a case", "plasma fleet pull --inventory fleet.json --case case-01"),
        ("Correlate", "plasma fleet correlate --case case-01"),
        ("Full scan", "plasma fleet scan --inventory fleet.json --case case-01"),
        ("Report", "plasma fleet report --case case-01"),
    ],
    safety=NETWORK + "; " + LOCAL_WRITE,
    see_also=["identity", "chain", "drift"],
))

_add("fleet pull", _c(
    "pull capped event tails from every inventory host into a case",
    """Read the inventory, validate each host entry, connect over the
selected transport, and copy a bounded event tail into the case directory.
The pull is capped by host and records per-host success/failure.

Inventory format: {"hosts":[{"name":"WS1","transport":"file","events_path":"..."}]}.
For winrm include endpoint and password_env; HTTPS is required unless the
entry explicitly accepts the lab risk.""",
    [
        ("File transport", "plasma fleet pull --inventory fleet.json --case case-01"),
        ("Bound the pull", "plasma fleet pull --inventory fleet.json --case case-01 --cap 5000 --window 3600"),
        ("With canaries", "plasma fleet pull --inventory fleet.json --case case-01 --canary finance-decoy"),
    ],
    safety=NETWORK + "; " + LOCAL_WRITE,
    notes=["Exit 1 when at least one host could not be pulled.",
           "The inventory is validated before any connection is made."],
    see_also=["fleet correlate", "fleet scan"],
))

_add("fleet correlate", _c(
    "correlate a pulled case for lateral movement and shared indicators",
    """Analyze the case's host tails for logon edges, shared source
addresses, common indicators, canary hits and hosts with no telemetry
(blind hosts). Returns ranked findings and a top score.

`--window` bounds how far apart two events may be to count as a link.""",
    [
        ("Correlate", "plasma fleet correlate --case case-01"),
        ("Wider window", "plasma fleet correlate --case case-01 --window 7200"),
    ],
    safety=LOCAL_WRITE,
    notes=["Exit 2 when findings are present."],
    see_also=["fleet pull", "fleet report"],
))

_add("fleet report", _c(
    "write a Markdown case report from the correlation",
    """Generate an analyst-readable report with the case summary, host
coverage, lateral edges, findings and evidence references. The Markdown is
printed and the report path is announced on stderr.""",
    [("Report", "plasma fleet report --case case-01")],
    safety=LOCAL_WRITE,
    output="Markdown on stdout; JSON error on failure.",
    see_also=["fleet correlate", "evidence"],
))

_add("fleet scan", _c(
    "one-shot pull, correlate and report",
    """Convenience wrapper for the full desk workflow: pull every host,
correlate the case, and write the report. It stops and exits 1 if no host
could be pulled. Exit 2 means correlation found something.""",
    [
        ("Scan", "plasma fleet scan --inventory fleet.json --case case-01"),
        ("Bounded scan", "plasma fleet scan --inventory fleet.json --case case-01 --cap 2000 --window 1800"),
    ],
    safety=NETWORK + "; " + LOCAL_WRITE,
    see_also=["fleet pull", "fleet correlate", "fleet report"],
))

_add("drift", _c(
    "record observatory answers as baselines and score what changed",
    """The operational question is rarely "is this host clean"; it is
"what changed since I last looked, and does it matter?" Record a named
observatory question as a baseline, then score a later run against it.

Baselines live under <root>/baselines/ and are explicit JSON, so a change
is explainable rather than a vendor black box.""",
    [
        ("Record", "plasma drift record attest"),
        ("Score", "plasma drift score attest"),
        ("List", "plasma drift list"),
    ],
    safety=LOCAL_WRITE,
    see_also=["observe", "watch", "fleet"],
))

_add("drift record", _c(
    "snapshot one observatory answer as the baseline for this host",
    """Run the named question, store the answer under the root and return
the baseline metadata. Re-recording replaces the prior baseline; do it
only after an expected change window.""",
    [
        ("Record attestation", "plasma drift record attest"),
        ("Record with custom canaries", "plasma drift record canary --canary finance-decoy,hr-decoy"),
    ],
    safety=LOCAL_WRITE,
    see_also=["drift score", "observe"],
))

_add("drift score", _c(
    "diff the current answer against the stored baseline",
    """Run the question again and compute a structured diff: added,
removed and changed items with a top score. Exit 2 means drift exists;
exit 1 means collection failed. A baseline that is missing is reported,
not treated as clean.""",
    [("Score", "plasma drift score attest")],
    safety=LOCAL_WRITE,
    see_also=["drift record", "watch"],
))

_add("drift list", _c(
    "list stored baselines and their age",
    """Return each baseline question, when it was recorded and the host it
belongs to. Use it to find stale baselines before trusting a clean score.""",
    [("List", "plasma drift list")],
    see_also=["drift record", "drift score"],
))

# ---------------------------------------------------------------------------
# Agent trust, audit and evidence
# ---------------------------------------------------------------------------

_add("control", _c(
    "agent trust layer: policy, approvals, audit, kill switch and tenants",
    """The deterministic control plane around agent-driven action. The model
never authorises itself: policy decides autonomy, scope, rate limits and
whether an approval is required. Every decision and action is written to a
hash-chained ledger that can be verified.

Kill switch: reads stay available; mutations are blocked while engaged.
Approvals are single-use and bound to the tool and argument hash.
Tenants scope hosts for MSSP-style separation.""",
    [
        ("Show policy", "plasma control policy show"),
        ("Set supervised autonomy", "plasma control policy set --autonomy supervised"),
        ("Engage the kill switch", "plasma control killswitch on --reason \"incident freeze\""),
        ("Verify the audit chain", "plasma control audit verify"),
    ],
    safety=LOCAL_WRITE,
    see_also=["actuate", "enforce", "evidence"],
))

_add("control policy", _c(
    "inspect or change the deterministic agent policy",
    """Policy decides autonomy tier, deny/allow lists, maximum actions and
hosts, and whether critical actions are permitted. It is local JSON, not
model output. Changes apply to subsequent tool calls.

Autonomy tiers: assist (plan only), supervised (plans plus approval),
autonomous (policy-allowed actions without per-action approval).""",
    [
        ("Show", "plasma control policy show"),
        ("Supervised", "plasma control policy set --autonomy supervised"),
        ("Tighten scope", "plasma control policy set --deny isolate_host --max-actions 2 --max-hosts 1"),
    ],
    safety=LOCAL_WRITE,
    see_also=["control policy show", "control policy set", "eval"],
))

_add("control policy show", _c(
    "print the effective agent policy",
    """Return the autonomy tier, deny/allow lists, limits, critical-action
setting and any defaults. Use it before asking an agent to act.""",
    [("Show", "plasma control policy show")],
    see_also=["control policy set"],
))

_add("control policy set", _c(
    "update the effective agent policy",
    """Set one or more policy fields. `--autonomy` chooses assist,
supervised or autonomous. `--deny` and `--allow` take tool names;
`--max-actions` and `--max-hosts` bound blast radius; `--allow-critical`
or `--no-allow-critical` controls critical actions.

Changes are local and immediate. Re-run `eval run` after tightening or
loosening policy.""",
    [
        ("Assist only", "plasma control policy set --autonomy assist"),
        ("Supervised with limits", "plasma control policy set --autonomy supervised --max-actions 2 --max-hosts 1"),
        ("Deny isolation", "plasma control policy set --deny isolate_host --no-allow-critical"),
    ],
    safety=LOCAL_WRITE,
    see_also=["control policy show", "eval"],
))

_add("control approvals", _c(
    "list, approve or deny single-use action approvals",
    """Approvals bind a tool call to its argument hash. They are single-use
and expire. An approval for one target cannot be replayed for another.
Use `approvals list` to see pending items, then approve or deny by id.""",
    [
        ("List", "plasma control approvals list"),
        ("Approve", "plasma control approvals approve 17 --approver alice --note \"reviewed\""),
        ("Deny", "plasma control approvals deny 17 --approver alice --note \"wrong host\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["enforce pending", "control policy"],
))

_add("control approvals list", _c(
    "list pending and recent approvals",
    """Return approval id, tool, argument hash, target summary, expiry and
state. `--limit` bounds the result.""",
    [("List", "plasma control approvals list --limit 50")],
    see_also=["control approvals approve", "control approvals deny"],
))

_add("control approvals approve", _c(
    "approve one pending request",
    """Record a human approval for the exact tool and argument hash. The
approver and optional note are stored in the ledger. The approval is
single-use.""",
    [("Approve", "plasma control approvals approve 17 --approver alice --note \"reviewed\"" )],
    safety=LOCAL_WRITE,
    see_also=["control approvals deny", "actuate apply"],
))

_add("control approvals deny", _c(
    "deny one pending request",
    """Record a denial with approver and note. The requesting agent receives
a structured refusal; the item cannot be replayed without a new request.""",
    [("Deny", "plasma control approvals deny 17 --approver alice --note \"not approved\"")],
    safety=LOCAL_WRITE,
    see_also=["control approvals approve"],
))

_add("control audit", _c(
    "read or verify the hash-chained provenance ledger",
    """Every decision and action is appended to a hash chain. `tail` shows
recent rows; `verify` recomputes the chain and exits 2 if a row was
modified, removed or reordered. This is the tamper-evidence layer an
auditor can check without trusting the agent.""",
    [
        ("Recent rows", "plasma control audit tail --last 50"),
        ("Verify", "plasma control audit verify"),
    ],
    safety=READ_ONLY,
    see_also=["control policy", "actuate journal", "evidence"],
))

_add("control audit tail", _c(
    "show the most recent ledger rows",
    """Return recent decisions, plans, applies, refusals and approvals with
the actor, tool, argument hash and result. `--last` bounds the output.""",
    [("Tail", "plasma control audit tail --last 100")],
    see_also=["control audit verify"],
))

_add("control audit verify", _c(
    "verify the ledger hash chain",
    """Recompute the chain from the first row. Exit 0 means intact; exit 2
means the chain is broken or a row is missing. Verification is read-only
and does not repair the ledger.""",
    [("Verify", "plasma control audit verify")],
    see_also=["control audit tail"],
))

_add("control killswitch", _c(
    "global or per-host stop for mutating actions",
    """Engage or release the kill switch. Reads remain available; every
mutating tool refuses while the switch is engaged. A per-host switch only
blocks that host. The reason and timestamp are recorded.

Check the switch before an autonomous run and engage it immediately during
anomalous agent behaviour.""",
    [
        ("Status", "plasma control killswitch status"),
        ("Engage globally", "plasma control killswitch on --reason \"agent anomaly\""),
        ("Engage for one host", "plasma control killswitch on --host WS1 --reason \"isolate change\""),
        ("Release", "plasma control killswitch off --reason \"review complete\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["actuate", "enforce"],
))

_add("control killswitch status", _c(
    "show the global and per-host kill-switch state",
    """Return whether the switch is engaged, for which hosts, when and why.
This is the first check before a mutating orchestration step.""",
    [("Status", "plasma control killswitch status")],
    see_also=["control killswitch on", "control killswitch off"],
))

_add("control killswitch on", _c(
    "engage the kill switch",
    """Block mutations globally or for one host, recording the reason and
time. Detection and read-only inspection continue.""",
    [
        ("Global", "plasma control killswitch on --reason \"incident freeze\""),
        ("One host", "plasma control killswitch on --host WS1 --reason \"change window\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["control killswitch off", "control killswitch status"],
))

_add("control killswitch off", _c(
    "release the kill switch",
    """Allow mutations again globally or for one host. The release is
recorded with its reason. Confirm the cause has been reviewed before
releasing.""",
    [
        ("Global", "plasma control killswitch off --reason \"review complete\""),
        ("One host", "plasma control killswitch off --host WS1 --reason \"change complete\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["control killswitch on", "control killswitch status"],
))

_add("control tenants", _c(
    "MSSP-style tenant registry and host scoping",
    """A tenant is a named group of hosts. Ledger rows carry the tenant and
policy can scope an agent to one tenant without changing the harness. Use
it when one desk manages multiple estates that must remain separated.""",
    [
        ("List", "plasma control tenants list"),
        ("Add", "plasma control tenants add acme --name \"Acme Corp\" --host WS1"),
        ("Remove", "plasma control tenants remove acme"),
    ],
    safety=LOCAL_WRITE,
    see_also=["control policy", "evidence"],
))

_add("control tenants list", _c(
    "list tenants and their hosts",
    """Return each tenant's id, display name and host membership.""",
    [("List", "plasma control tenants list")],
    see_also=["control tenants add", "control tenants remove"],
))

_add("control tenants add", _c(
    "create or update a tenant and bind a host",
    """Register a tenant id with an optional display name and host. Adding
an existing tenant updates it. Host scoping is enforced by policy, not by
this command alone.""",
    [("Add", "plasma control tenants add acme --name \"Acme Corp\" --host WS1")],
    safety=LOCAL_WRITE,
    see_also=["control tenants list", "control policy"],
))

_add("control tenants remove", _c(
    "remove a tenant",
    """Remove the tenant registry entry. Hosts and ledger history are not
deleted; the separation rule simply no longer applies to future policy
checks. Review audit requirements before removing a tenant.""",
    [("Remove", "plasma control tenants remove acme")],
    safety=LOCAL_WRITE,
    see_also=["control tenants list"],
))

_add("evidence", _c(
    "machine-generated compliance evidence",
    """Turn the estate's real state into auditor-readable control evidence:
events, coverage, policy, approvals, kill switch, provenance chain and
tenants. It does not invent a claim; every row cites the artifact it came
from.

Frameworks: CBN, NDPA, PCI DSS and ISO 27001. Output is JSON plus a
Markdown companion.""",
    [
        ("CBN", "plasma evidence export --framework cbn"),
        ("PCI to a file", "plasma evidence export --framework pci --out pci-evidence.json"),
    ],
    safety=LOCAL_WRITE,
    see_also=["assurance", "control audit", "coverage"],
))

_add("evidence export", _c(
    "export the control matrix for one framework",
    """Read current Plasma state and write the framework's control matrix
as JSON, with a Markdown companion next to it. Missing evidence is shown
as missing, not as a pass.""",
    [
        ("Default framework", "plasma evidence export"),
        ("ISO 27001", "plasma evidence export --framework iso27001 --out evidence.json"),
    ],
    safety=LOCAL_WRITE,
    notes=["Run after collection and audit verification so the matrix is "
           "not empty.",
           "The output can contain hostnames and event summaries; handle it "
           "as sensitive."],
    see_also=["assurance support-bundle", "control audit verify"],
))

_add("assurance", _c(
    "SBOM, safety case, support bundle and third-party notices",
    """Assurance artifacts for procurement, auditors and support. The SBOM
describes shipped components; the safety case renders the argument and
its evidence; the support bundle is redacted for sharing; notices lists
third-party licenses.

None of these commands change the host.""",
    [
        ("SBOM", "plasma assurance sbom"),
        ("Safety case", "plasma assurance safety-case"),
        ("Support bundle", "plasma assurance support-bundle"),
        ("Notices", "plasma assurance notices"),
    ],
    safety=LOCAL_WRITE,
    see_also=["evidence", "control audit"],
))

_add("assurance sbom", _c(
    "write a software bill of materials",
    """Emit a JSON SBOM of the shipped components, versions and licenses.
Use --out to write it to a file; otherwise the result is returned in the
command output.""",
    [("SBOM to a file", "plasma assurance sbom --out sbom.json")],
    safety=LOCAL_WRITE,
    see_also=["assurance notices", "status"],
))

_add("assurance safety-case", _c(
    "generate the safety-case narrative and evidence index",
    """Render the safety argument: claims, the evidence that supports them,
and gaps. This is generated from real state, so a missing control appears
as a gap rather than a claim.""",
    [("Safety case", "plasma assurance safety-case --out safety-case.md")],
    safety=LOCAL_WRITE,
    see_also=["evidence", "assurance support-bundle"],
))

_add("assurance support-bundle", _c(
    "build a redacted support bundle",
    """Collect configuration, health, versions, recent audit rows and
diagnostics into a bundle for support. Secrets and raw command lines are
redacted. Review the bundle before sending it outside the estate.""",
    [("Bundle", "plasma assurance support-bundle --out support.zip")],
    safety=LOCAL_WRITE,
    notes=["The bundle is redacted but still sensitive; share it through an "
           "approved channel."],
    see_also=["assurance sbom", "health"],
))

_add("assurance notices", _c(
    "print third-party license notices",
    """Print the bundled components and their license notices. This is a
text report, intended for redistribution with the product.""",
    [("Notices", "plasma assurance notices")],
    safety=READ_ONLY,
    output="Text on stdout.",
    see_also=["assurance sbom"],
))

# ---------------------------------------------------------------------------
# Updates and deployment
# ---------------------------------------------------------------------------

_add("update", _c(
    "signed self-update from GitHub releases",
    """Check, download, verify and install a newer signed release. SHA-256
sums and a pinned Authenticode signer are both checked before the new
executable is run. The previous binary is kept for rollback.

`update auto` is the measured path used by the daily PlasmaUpdate task:
ring-aware, maintenance-window aware, canary-held, kill-switch aware and
single-flight.""",
    [
        ("Check", "plasma update check"),
        ("Apply latest", "plasma update apply"),
        ("Measured automatic path", "plasma update auto --check-only"),
        ("Force reinstall", "plasma update auto --force"),
    ],
    safety=NETWORK + "; " + HOST_WRITE,
    see_also=["ring", "rollback", "protect"],
))

_add("update check", _c(
    "compare the installed version with the latest release",
    """Fetch the latest release metadata and report current, latest,
whether an update is available and the publication time. It does not
download or execute anything.""",
    [
        ("Default repo", "plasma update check"),
        ("Custom repo", "plasma update check --repo owner/name"),
    ],
    safety=NETWORK,
    see_also=["update apply", "update auto"],
))

_add("update apply", _c(
    "download, verify and install a signed release",
    """Download the release asset and SHA256SUMS, verify the checksum and
the pinned Authenticode signer, run the new installer, quiesce the tasks
holding the binary, rotate the running and canonical binaries, and restart
the tasks. Apply is explicit and synchronous; use `update auto` for the
scheduled path.

`--allow-unsigned` is a development escape and should not be used in
production.""",
    [
        ("Latest", "plasma update apply"),
        ("Specific tag", "plasma update apply --tag v1.19.0"),
        ("Custom root", "plasma update apply --root D:\\Plasma"),
    ],
    safety=NETWORK + "; " + HOST_WRITE + "; " + PRIVILEGED,
    notes=["Unsigned or wrong-signer assets are refused.",
           "The previous binary is kept as .old; use `rollback` to restore."],
    see_also=["update check", "update auto", "rollback"],
))

_add("update auto", _c(
    "check and apply the latest release under the measured policy",
    """The self-update policy. It skips when automatic updates are disabled,
the kill switch is engaged, the host is outside its maintenance window, or
the host is not in the effective ring. Broad hosts wait for the 24-hour
canary hold; canary hosts update immediately; rollback hosts never update.

With `--check-only`, it reports `update_available` without changing the
host and exits 2 when an update is available. With `--force`, it reinstalls
even when the version matches (useful for repair).""",
    [
        ("Check only", "plasma update auto --check-only"),
        ("Apply if due", "plasma update auto"),
        ("Force repair", "plasma update auto --force --no-notify"),
        ("Canary override", "plasma update auto --ring canary"),
    ],
    safety=NETWORK + "; " + HOST_WRITE + "; " + PRIVILEGED,
    notes=["The installer registers PlasmaUpdate to run this daily at ~03:00.",
           "Broad hosts wait 24 hours; a host assignment wins over config.",
           "State and history: update-state.json and update-journal.jsonl."],
    see_also=["update check", "update apply", "ring", "rollback"],
))

_add("ring", _c(
    "deployment rings for staged updates",
    """Canary hosts take a release first; broad hosts wait for the hold;
rollback hosts never auto-update (rollback is a policy state, not a
membership list; use `plasma rollback` to restore a binary). Membership is
a local, human-set fact.
`assign` binds a host, `promote` changes the default ring, `status` shows
the map.""",
    [
        ("Status", "plasma ring status"),
        ("Assign WS1", "plasma ring assign WS1 --ring canary"),
        ("Promote broad", "plasma ring promote broad"),
    ],
    safety=LOCAL_WRITE,
    see_also=["update auto", "rollback"],
))

_add("ring status", _c(
    "show ring membership and the current default",
    """Return the current default and each ring's hosts. An unassigned host
uses the configured default; a host assigned to canary updates immediately
even when the default is broad.""",
    [("Status", "plasma ring status")],
    see_also=["ring assign", "ring promote"],
))

_add("ring assign", _c(
    "assign a host to a ring",
    """Add the host to canary or broad, removing it from the other ring
first. Assignment is the authoritative local fact used by `update auto`.""",
    [
        ("Canary", "plasma ring assign WS1 --ring canary"),
        ("Broad", "plasma ring assign WS2 --ring broad"),
    ],
    safety=LOCAL_WRITE,
    see_also=["ring status", "update auto"],
))

_add("ring promote", _c(
    "set the default ring",
    """Change the default ring used when a host has no explicit assignment.
This does not move hosts between rings.""",
    [("Promote", "plasma ring promote broad")],
    safety=LOCAL_WRITE,
    see_also=["ring status", "ring assign"],
))

_add("rollback", _c(
    "restore the previous Plasma binary",
    """Swap the canonical binary back to the .old copy retained by the
updater. The current binary is moved aside, so rollback is itself
reversible. Use it when a new release regresses detection or stability.""",
    [
        ("Default binary", "plasma rollback"),
        ("Explicit binary", "plasma rollback --bin C:\\ProgramData\\Plasma\\bin\\plasma.exe"),
    ],
    safety=HOST_WRITE + "; " + PRIVILEGED,
    notes=["Restart long-running tasks after rollback so they load the "
           "restored binary.",
           "Rollback changes the binary, not the event store or policy."],
    see_also=["update apply", "update auto", "ring"],
))

_add("_bridge", _c(
    "internal bridge used by the frozen executable",
    """Hidden entry point used by the packaged payload. It is not a stable
operator interface and is excluded from the recommended workflow.""",
    [("Do not call directly", "plasma _bridge --help")],
    safety=LOCAL_WRITE,
    hidden=True,
))

# ---------------------------------------------------------------------------
# Rendering and introspection
# ---------------------------------------------------------------------------

ROOT_DESCRIPTION = """Plasma is a lake-less, agent-native Windows EDR.

Detection is local: Sysmon/WHIDS alerts, Security-channel audit events, an
ETW tap, DTrace on demand, file integrity, canary files, native DNS/HTTP
tokens, on-demand memory scanning and an active file/registry/pipe canary
shield are normalized into one JSONL store. Investigation is local too: typed queries, explicit process lineage, bounded
summaries and sealed case directories. Prevention is opt-in: AppLocker,
egress, ASR, LSA, Controlled Folder Access, Network Protection and the
driver blocklist are previewed, plan-gated and reversible; WDAC is read-only.
Response is explicit: every action is scoped, journaled and reversible, and
automatic containment is armed narrowly by default. The agent trust layer
decides what an agent may do; the kill switch always wins.

Every command prints JSON. Exit codes are part of the contract:
0 success/clean, 1 data/input error, 2 refused/findings/attention,
3 execution or verification failure."""

ROOT_EPILOG = """AGENT QUICK START
  1. plasma help --json                      # discover every command
  2. plasma status                           # what is installed
  3. plasma health                           # is the stack alive
  4. plasma watch once                       # detect and decide
  5. plasma query --kind alert --since 1h    # typed, bounded investigation
  6. plasma case open IR-1 && plasma case add IR-1 --process <name>
  7. plasma prevent posture                  # what enforcement is available
  8. plasma prevent cfa --mode audit         # preview a reversible control
  9. plasma control killswitch status        # is mutation allowed
 10. plasma actuate apply ... --reason ...   # dry-run; prints a plan id
 11. plasma actuate apply ... --apply --plan <id>

DISCOVERY
  plasma help                    command map and conventions
  plasma help <command path>     detailed help with examples
  plasma help --json             full machine-readable catalog
  plasma <command> --help        argparse help plus examples

CONVENTIONS
  --root     Plasma state root (default: C:\\ProgramData\\Plasma on Windows)
  --events   JSONL event store; collection appends, scoring is read-only
  Mutating response commands are dry-run by default and require a seen
  plan id: --apply --plan <id>. The kill switch blocks mutations.
  Protected services, processes, accounts and paths are refused even when
  a caller asks directly. See: plasma protect protected.

EXIT CODES
  0 success or clean
  1 data, input or collection error
  2 refused, drift/findings present, or attention needed
  3 execution, verification or installation failure"""


def _spec(path: tuple[str, ...]) -> dict | None:
    return COMMANDS.get(" ".join(path))


def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    """Yield (path, parser) for the root and every node, depth first."""
    yield path, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from _walk(child, path + (name,))


def _children(parser: argparse.ArgumentParser) -> list[tuple[str, argparse.ArgumentParser]]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return list(action.choices.items())
    return []


def render_epilog(spec: dict) -> str:
    lines = ["EXAMPLES"]
    for title, command in spec["examples"]:
        lines.append(f"  {title}:")
        lines.append(f"    {command}")
    if spec["notes"]:
        lines.append("")
        lines.append("NOTES")
        for note in spec["notes"]:
            lines.append(f"  - {note}")
    lines.append("")
    lines.append("SAFETY")
    lines.append(f"  {spec['safety']}")
    lines.append("")
    lines.append("OUTPUT")
    lines.append(f"  {spec['output']}")
    if spec["see_also"]:
        lines.append("")
        lines.append("SEE ALSO")
        lines.append("  " + ", ".join(spec["see_also"]))
    return "\n".join(lines)


class _ChoiceHelp(argparse.Action):
    """Minimal pseudo-action used to describe one subcommand in a parent list."""

    def __init__(self, name: str, help_text: str):
        super().__init__(option_strings=[], dest=name, metavar=name,
                         help=help_text)


def _annotate(parser: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    # A custom root usage string otherwise leaks into child parsers created
    # by add_parser(). Re-anchor every prog to its real command path.
    parser.prog = "plasma" if not path else "plasma " + " ".join(path)
    if not path:
        parser.description = ROOT_DESCRIPTION
        parser.epilog = ROOT_EPILOG
    else:
        spec = _spec(path)
        if spec:
            parser.description = spec["description"]
            parser.epilog = render_epilog(spec)
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        visible = [(name, child) for name, child in action.choices.items()
                   if not name.startswith("_")]
        action.metavar = "{" + ",".join(name for name, _ in visible) + "}"
        # Rebuild the choice list so every subcommand gets a summary, even
        # when the parser was created without an explicit help= argument.
        action._choices_actions = [
            _ChoiceHelp(
                name, (_spec(path + (name,)) or {}).get("summary", ""))
            for name, _ in visible
        ]
        for name, child in action.choices.items():
            _annotate(child, path + (name,))


def install(parser: argparse.ArgumentParser) -> None:
    """Attach detailed descriptions, examples and choice help to every node."""
    _annotate(parser, ())


def find_parser(parser: argparse.ArgumentParser,
                words: list[str] | tuple[str, ...]):
    if words and (_spec(tuple(words)) or {}).get("hidden"):
        return None
    current = parser
    for word in words:
        match = None
        for name, child in _children(current):
            if name == word:
                match = child
                break
        if match is None:
            return None
        current = match
    return current


def _action_dict(action: argparse.Action) -> dict:
    row: dict[str, Any] = {
        "dest": action.dest,
        "required": bool(action.required),
        "help": (action.help if action.help is not argparse.SUPPRESS else None),
        "nargs": None if action.nargs is None else str(action.nargs),
        "action": type(action).__name__,
    }
    if action.option_strings:
        row["option_strings"] = list(action.option_strings)
        row["positional"] = False
    else:
        row["option_strings"] = []
        row["positional"] = True
    if action.choices is not None:
        row["choices"] = [str(c) for c in action.choices]
    if action.metavar:
        row["metavar"] = str(action.metavar)
    if action.default is not None and action.default is not False \
            and action.default is not argparse.SUPPRESS:
        try:
            row["default"] = str(action.default)
        except Exception:  # noqa: BLE001, S110 - introspection is best effort
            pass
    if action.type is not None and callable(action.type):
        row["type"] = getattr(action.type, "__name__", str(action.type))
    return row


def _node_dict(path: tuple[str, ...], parser: argparse.ArgumentParser) -> dict:
    spec = _spec(path) or {}
    children = _children(parser)
    args = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        if isinstance(action, argparse._HelpAction):
            continue
        args.append(_action_dict(action))
    group_key = None
    if path:
        for key, _title, names in GROUPS:
            if path[0] in names:
                group_key = key
                break
    return {
        "command": " ".join(path),
        "path": list(path),
        "group": group_key,
        "summary": spec.get("summary", ""),
        "description": spec.get("description", ""),
        "usage": parser.format_usage().strip(),
        "leaf": not children,
        "subcommands": [
            {
                "name": name,
                "summary": (_spec(path + (name,)) or {}).get("summary", ""),
            }
            for name, _child in children
        ],
        "arguments": args,
        "examples": [
            {"title": title, "command": command}
            for title, command in spec.get("examples", [])
        ],
        "notes": spec.get("notes", []),
        "safety": spec.get("safety", ""),
        "output": spec.get("output", "JSON on stdout."),
        "see_also": spec.get("see_also", []),
        "hidden": bool(spec.get("hidden", False)),
    }


def catalog(parser: argparse.ArgumentParser) -> dict:
    """Return the complete help catalog as a JSON-serializable object."""
    rows = []
    for path, node in _walk(parser):
        if not path or (_spec(path) or {}).get("hidden"):
            continue
        rows.append(_node_dict(path, node))
    rows.sort(key=lambda row: (row["group"] or "zz", row["command"]))
    return {
        "schema": "plasma.help/1",
        "product": "Plasma",
        "version": __version__,
        "summary": "Complete command catalog for the Plasma CLI.",
        "discovery": {
            "human": "plasma help",
            "topic": "plasma help <command path>",
            "json": "plasma help --json",
            "single": "plasma help <command path> --json",
            "argparse": "plasma <command> --help",
        },
        "groups": [
            {"key": key, "title": title, "commands": list(names)}
            for key, title, names in GROUPS
        ],
        "commands": rows,
        "exit_codes": EXIT_CODES,
        "conventions": COMMON_CONVENTIONS,
        "environment": ENVIRONMENT,
    }


def command_json(parser: argparse.ArgumentParser,
                 words: list[str] | tuple[str, ...]) -> dict | None:
    target = find_parser(parser, words)
    if target is None or not words:
        return None
    return _node_dict(tuple(words), target)


def overview(parser: argparse.ArgumentParser) -> str:
    """Human-readable command map and agent workflow."""
    lines = [
        f"Plasma {__version__} - agent-oriented command reference",
        "",
        "Start with `plasma help --json` when a machine is orchestrating;",
        "it returns every command, argument, example and safety class.",
        "",
        "AGENT WORKFLOW",
        "  1. plasma help --json",
        "  2. plasma status",
        "  3. plasma health",
        "  4. plasma watch once",
        "  5. plasma control killswitch status",
        "  6. plasma actuate apply <action> --target <t> --reason <r>",
        "  7. plasma actuate apply <action> --target <t> --reason <r>"
        " --apply --plan <id>",
        "  8. plasma actuate journal --last 20",
        "",
    ]
    for key, title, names in GROUPS:
        lines.append(title.upper())
        for name in names:
            spec = COMMANDS.get(name)
            if not spec or spec.get("hidden"):
                continue
            lines.append(f"  {name:<12} {spec['summary']}")
        lines.append("")
    lines.append("DISCOVERY")
    lines.append("  plasma help                       this page")
    lines.append("  plasma help <command path>        detailed help + examples")
    lines.append("  plasma help --json                full catalog")
    lines.append("  plasma <command> --help           argparse syntax + examples")
    lines.append("")
    lines.append("EXIT CODES")
    for code, meaning in EXIT_CODES.items():
        lines.append(f"  {code}  {meaning}")
    lines.append("")
    lines.append("CONVENTIONS")
    for text in COMMON_CONVENTIONS:
        lines.append(f"  - {text}")
    lines.append("")
    lines.append("ENVIRONMENT")
    for row in ENVIRONMENT:
        lines.append(f"  {row['name']:<28} {row['meaning']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Investigation: typed query, lineage, case workspace (v1.23.0)
# ---------------------------------------------------------------------------

_add("query", _c(
    "typed, bounded queries over the local event store",
    """Ask a precise question of the bounded JSONL event tail without
assembling a shell pipeline.

The query language is closed: `host`, `user`, `process`, `parent`, `kind`,
`source`, `event_id`, `technique`, `contains`, `regex`, `since`, `until`,
`min_score`, `max_score`, `pid`, `count_by`, `order`, `limit` and
`max_rows`. An unknown field is refused, not ignored, so a typo cannot
silently widen a search. Process and parent comparisons use the basename,
case-insensitively, and accept `*`/`?` globs.

Rows are read from the last `--max-rows` (default 5000) within an 8 MiB
tail. `--out` writes the full result JSON locally.""",
    [
        ("Recent PowerShell processes", "plasma query --process powershell.exe --since 1h"),
        ("High-score alerts by process", "plasma query --kind alert --min-score 0.7 --count-by process"),
        ("Specific user on one host", "plasma query --host WS1 --user CORP\\olu --since 24h"),
        ("Reusable JSON spec", "plasma query --spec incident-42-query.json"),
        ("Write the result to a file", "plasma query --process rundll32.exe --out C:\\Temp\\rundll32.json"),
    ],
    safety=READ_ONLY,
    notes=["Unknown filter names fail closed.",
           "The search is a bounded tail, not a database query.",
           "Use `plasma tree` when the question is about lineage."],
    see_also=["tree", "case add", "chain", "coverage"],
))

_add("tree", _c(
    "parent/child process lineage from explicit PID edges",
    """Build a process tree from explicit `pid`/`ppid` edges in the event
tail. Select a root by `--pid` or `--process`; with neither, the most recent
five orphan roots are returned.

A missing parent is reported as an orphan rather than guessed from a process
name. A wrong lineage edge is worse than no edge in an investigation.
Depth is capped at 10 and the result at 500 nodes; truncation is explicit.""",
    [
        ("Tree for a PID", "plasma tree --pid 4832"),
        ("Tree for the newest PowerShell", "plasma tree --process powershell.exe --depth 2"),
        ("Wider history", "plasma tree --pid 1200 --max-rows 10000 --depth 5"),
    ],
    safety=READ_ONLY,
    notes=["Only explicit ppid edges are used.",
           "Sysmon EID 1 and Security 4688 both populate ppid when available."],
    see_also=["query", "case add", "chain"],
))

_add("case", _c(
    "durable local case workspace",
    """Create a case directory under `<root>/cases/<name>` and collect
selected events, findings and operator notes into it. A case is plain files:
portable into a ticket or evidence bundle, with no server and no database.

`case seal` hashes every artifact and writes a manifest with a chain hash;
`case verify` recomputes it and fails on any changed or missing file.""",
    [
        ("Open a case", "plasma case open IR-2026-042 --host WS1 --title \"LSASS access\""),
        ("Collect matching events", "plasma case add IR-2026-042 --process lsass.exe --since 2h"),
        ("Add an operator note", "plasma case note IR-2026-042 \"Confirmed with the user\""),
        ("Render and seal", "plasma case report IR-2026-042 && plasma case seal IR-2026-042"),
    ],
    safety=LOCAL_WRITE,
    notes=["Reopening a case never clears evidence.",
           "`case add` refuses to run without a filter; copying the whole store is not a case."],
    see_also=["case open", "case add", "case report", "case seal", "query"],
))

_add("case open", _c(
    "create or reopen a local case",
    """Create `<root>/cases/<name>/` with `case.json`, `events.jsonl`,
`findings.jsonl` and `notes.md`. Reopening an existing case preserves all
artifacts and appends an optional note.""",
    [
        ("Create", "plasma case open IR-2026-042 --host WS1"),
        ("Reopen with a note", "plasma case open IR-2026-042 --note \"Second review\""),
    ],
    safety=LOCAL_WRITE,
    see_also=["case add", "case list"],
))

_add("case list", _c(
    "list local cases",
    "Return case metadata, newest first, from `<root>/cases/*/case.json`.",
    [("List", "plasma case list")],
    safety=READ_ONLY,
    see_also=["case open", "case report"],
))

_add("case add", _c(
    "query events and copy matches into a case",
    """Run the same typed query language as `plasma query` and append the
matching rows to the case. Duplicate rows are not appended twice. A filter
is mandatory: a case is a selection, not a copy of the diary.""",
    [
        ("By process", "plasma case add IR-2026-042 --process powershell.exe --since 2h"),
        ("By technique", "plasma case add IR-2026-042 --technique T1055 --min-score 0.7"),
        ("From a spec", "plasma case add IR-2026-042 --spec query.json"),
    ],
    safety=LOCAL_WRITE,
    notes=["The source store is never modified.",
           "Returns how many rows were added and how many matched."],
    see_also=["query", "case timeline", "case report"],
))

_add("case note", _c(
    "append an operator note to a case",
    "Append a timestamped line to `notes.md`. Notes participate in the timeline and report.",
    [("Add a note", "plasma case note IR-2026-042 \"Isolation approved by the duty manager\"")],
    safety=LOCAL_WRITE,
    see_also=["case timeline", "case report"],
))

_add("case timeline", _c(
    "merge events, findings and notes into one timeline",
    "Return a time-ordered view of the case. Events and findings keep their score; notes are source `operator`.",
    [("Timeline", "plasma case timeline IR-2026-042")],
    safety=READ_ONLY,
    see_also=["case note", "case report"],
))

_add("case report", _c(
    "render a Markdown case report",
    """Write `report.md` inside the case with counts, score bands, event
kinds, sources, the highest-scoring rows and operator notes.""",
    [
        ("Render in place", "plasma case report IR-2026-042"),
        ("Render elsewhere", "plasma case report IR-2026-042 --out C:\\Temp\\IR-2026-042.md"),
    ],
    safety=LOCAL_WRITE,
    see_also=["case seal", "case timeline"],
))

_add("case seal", _c(
    "seal a case with a hash manifest",
    """Hash every artifact and write `manifest.json` with per-file SHA-256
and a chain hash. Sealing is not encryption; it is tamper evidence.""",
    [("Seal", "plasma case seal IR-2026-042")],
    safety=LOCAL_WRITE,
    notes=["Renders `report.md` first if it does not exist.",
           "The manifest excludes itself from its own hash set."],
    see_also=["case verify", "evidence"],
))

_add("case verify", _c(
    "verify a sealed case has not changed",
    "Recompute every artifact hash and the chain hash. Exit 2 on any changed or missing file.",
    [("Verify", "plasma case verify IR-2026-042")],
    safety=READ_ONLY,
    output="JSON with `code` VERIFIED or TAMPERED.",
    see_also=["case seal"],
))

_add("memory triage", _c(
    "scan processes selected from high-signal alerts",
    """Select recent PIDs from injection- or credential-shaped alerts and run
one bounded HollowsHunter scan against them. A high score alone is not
enough; the technique or event shape must justify a memory scan. The default
window is 60 minutes and the default cap is five targets.""",
    [
        ("Default triage", "plasma memory triage"),
        ("Wider window", "plasma memory triage --since-minutes 240 --max-targets 10"),
        ("Stricter threshold", "plasma memory triage --min-score 0.9"),
    ],
    safety=LOCAL_WRITE,
    notes=["Requires the pinned HollowsHunter payload, like `memory scan`.",
           "No target produces `NO_TARGETS`, not an error.",
           "Findings are deduplicated across repeated triage runs."],
    see_also=["memory scan", "health", "query"],
))

_add("control policy simulate", _c(
    "explain a policy decision without changing anything",
    """Run the deterministic policy engine against a typed tool call and
return the exact decision, reasons and policy hash. No action, approval or
ledger row is created.

By default the simulated context holds exactly the scopes the tool declares.
Use `--scopes` to model a narrower harness.""",
    [
        ("Would isolation be allowed?", "plasma control policy simulate isolate_host --args '{\"host\":\"WS1\"}'"),
        ("Model a read-only harness", "plasma control policy simulate isolate_host --scopes events:read"),
        ("Model kill switch", "plasma control policy simulate kill_process --args '{\"pid\":42}' --killswitch-blocked"),
    ],
    safety=READ_ONLY,
    notes=["Read-only: this is the safe way to test an autonomy change.",
           "Use `--recent-actions` to model the rate limit."],
    see_also=["control policy show", "control policy set", "mcp"],
))


_add("summarize", _c(
    "bounded local digest of processes, lineage, users and rare commands",
    """Reduce a bounded event tail to a small map: process first/last seen,
parent→child frequencies, top users and hosts, score bands, sources and
rare command lines. This is the fast orientation step before a typed query
or a case.

The output is lossy by design. Every section is capped by `--limit`; the
result sets `truncated` when more existed.""",
    [
        ("Last hour", "plasma summarize --since 1h"),
        ("Wider map", "plasma summarize --since 24h --limit 50"),
        ("Rare commands only", "plasma summarize --since 6h --rare-max 1"),
    ],
    safety=READ_ONLY,
    notes=["First/last timestamps are UTC ISO values from the event rows.",
           "Rare command lines are whitespace-normalized and capped at 300 chars."],
    see_also=["query", "tree", "case add"],
))

_add("detect", _c(
    "detection-engineering harness",
    """Validate, diff and replay written detection content without a running
WHIDS service. Validation compiles every regex and checks condition
variables; diff compares rule files by name and content hash; replay runs
the chain engine and a bounded summary over a captured store.""",
    [
        ("Validate baseline", "plasma detect validate --rules sensors/plasma-baseline.gen"),
        ("Run regression cases", "plasma detect test"),
        ("Diff two rule sets", "plasma detect diff --old old.gen --new new.gen"),
        ("Replay a capture", "plasma detect replay --events captured.jsonl"),
    ],
    safety=READ_ONLY,
    notes=["Replay is deterministic; the model is not involved.",
           "Promotion is intentionally left to the existing install/whids path."],
    see_also=["detect validate", "detect diff", "detect replay", "coverage"],
))

_add("detect validate", _c(
    "compile and structurally validate a rule file",
    """Parse a JSON or JSONL rule file, require a Name and Matches list,
compile every `~=` regex, detect duplicate names and warn when a Condition
references a variable no Matches line defines.""",
    [("Validate", "plasma detect validate --rules sensors/plasma-baseline.gen")],
    safety=READ_ONLY,
    output="JSON with errors, warnings and duplicate names.",
    see_also=["detect diff", "detect replay"],
))

_add("detect diff", _c(
    "compare two rule files",
    "Report rules added, removed and changed by name and SHA-256 of the canonical rule object.",
    [("Diff", "plasma detect diff --old sensors/plasma-baseline.gen --new candidate.gen")],
    safety=READ_ONLY,
    see_also=["detect validate"],
))

_add("detect replay", _c(
    "replay deterministic detection over a captured store",
    """Run the chain engine and a bounded summary over a captured JSONL
store. Use this to see how a rule change or a chain change behaves against
real history before touching a live sensor.""",
    [("Replay", "plasma detect replay --events captured.jsonl --max-rows 10000")],
    safety=READ_ONLY,
    see_also=["detect validate", "chain score", "summarize"],
))


_add("prevent posture", _c(
    "read the WDAC, CFA, Network Protection and driver-blocklist state",
    """Read, without changing anything, the Windows enforcement points Plasma
delegates inline prevention to: active WDAC policy files, Defender
Controlled Folder Access, Network Protection, the vulnerable driver
blocklist, ASR rule counts, real-time protection and tamper protection.

The result names the gaps. It is the inventory behind `plasma prevent`.""",
    [
        ("Show posture", "plasma prevent posture"),
        ("Check on a fleet host", "plasma serve  # then GET /v1/exec with prevent posture"),
    ],
    safety=READ_ONLY,
    notes=["Read-only PowerShell; no Defender setting is changed.",
           "WDAC policies are counted from the active Code Integrity store."],
    see_also=["prevent status", "prevent asr", "health"],
))

_add("detect test", _c(
    "run deterministic hit/miss detection regression cases",
    """Run a built-in suite of positive and negative chain cases, or a JSON
case file. Each case names a chain, supplies events, and expects a hit or a
miss. The suite is intentionally small and deterministic: it catches broken
chain logic, not unknown malware.""",
    [
        ("Built-in suite", "plasma detect test"),
        ("Custom cases", "plasma detect test --cases detection-cases.json"),
    ],
    safety=READ_ONLY,
    output="JSON with passed, failed and per-case results.",
    notes=["Exit 2 when any case fails.",
           "A hit case can also require a minimum score."],
    see_also=["detect validate", "detect replay", "chain score"],
))

_add("prevent cfa", _c(
    "Controlled Folder Access: preview, apply or roll back",
    """Preview or change Defender Controlled Folder Access. Modes are off,
audit and block. Apply requires a plan id from the preview and a reason;
the current value is captured and journaled for rollback.

The default is audit. A policy-managed host may ignore the local setting;
apply verifies the resulting value and fails rather than claiming success.""",
    [
        ("Preview audit", "plasma prevent cfa --mode audit"),
        ("Apply previewed audit", "plasma prevent cfa --mode audit --apply --plan 7 --reason \"pilot\""),
        ("Roll back", "plasma prevent rollback --id 7"),
    ],
    safety=PLAN_GATED,
    notes=["CFA can break line-of-business apps; pilot in audit first.",
           "Rollback restores the captured previous value."],
    see_also=["prevent posture", "prevent rollback", "prevent network"],
))

_add("prevent network", _c(
    "Network Protection: preview, apply or roll back",
    """Preview or change Defender Network Protection. Modes are off, audit
and block. Apply requires a plan id from the preview and a reason; the
current value is captured and journaled for rollback.

The default is audit. Verification catches a policy override.""",
    [
        ("Preview audit", "plasma prevent network --mode audit"),
        ("Apply previewed block", "plasma prevent network --mode block --apply --plan 8 --reason \"pilot\""),
        ("Roll back", "plasma prevent rollback --id 8"),
    ],
    safety=PLAN_GATED,
    notes=["Network Protection can affect browsers and updaters; pilot in audit first.",
           "Rollback restores the captured previous value."],
    see_also=["prevent posture", "prevent rollback", "prevent cfa"],
))

_add("prevent driver-blocklist", _c(
    "Microsoft vulnerable driver blocklist: preview, apply or roll back",
    """Preview or set the Microsoft vulnerable driver blocklist switch.
Apply requires a plan id and a reason; the previous registry value is
captured for rollback. A system restart may be required before the change
is fully effective.""",
    [
        ("Preview enable", "plasma prevent driver-blocklist"),
        ("Apply previewed enable", "plasma prevent driver-blocklist --apply --plan 9 --reason \"baseline\""),
        ("Preview the opposite direction", "plasma prevent driver-blocklist --off"),
    ],
    safety=PLAN_GATED,
    notes=["Rollback restores or removes the registry value.",
           "Plasma does not restart the host."],
    see_also=["prevent posture", "prevent rollback"],
))

_add("canary shield", _c(
    "active canary shield: kill the process that writes or deletes a canary",
    """Turn the canary from a detector into a narrow active defence.

A `canary shield install` dry-run adds Sysmon `FileCreate`/`FileDelete`
includes for the deployed canary basenames, adds `RegistryEvent` includes
for decoy registry keys, and registers a SYSTEM task that runs
`canary shield sweep --apply` every minute. The sweep proves the accessing
process still exists and still matches the recorded image, refuses protected
and trusted processes, then kills the process and journals the decision.

Only create/overwrite/delete and registry writes trigger. Merely opening or
reading a canary does not. Explorer and common backup/AV/system processes
are skipped; the false-positive boundary is explicit, not implied.""",
    [
        ("Status", "plasma canary shield status"),
        ("Preview install", "plasma canary shield install"),
        ("Arm after review", "plasma canary shield install --apply --plan 4 --reason \"IR-42 shield\""),
        ("Dry-run one sweep", "plasma canary shield sweep --since-minutes 10"),
        ("Kill on a live sweep", "plasma canary shield sweep --apply --reason \"canary tripped\""),
        ("Disarm", "plasma canary shield uninstall --apply --plan 5 --reason \"change window\""),
    ],
    safety=PLAN_GATED,
    notes=["Requires Sysmon and a canonical <root>\\\\bin\\\\plasma.exe.",
           "Kills are capped per sweep and refused for protected processes.",
           "The task runs every minute; the kill is near-real-time, not in-kernel."],
    see_also=["canary deploy", "canary registry deploy", "canary shield status",
              "watch once", "actuate"],
))

_add("canary shield status", _c(
    "shield task, canary counts and last sweep",
    "Report whether the shield task is installed, how many file and registry canaries exist, whether the Sysmon config contains the narrow includes, and the last sweep result.",
    [("Status", "plasma canary shield status")],
    safety=READ_ONLY,
    see_also=["canary shield", "canary shield sweep"],
))

_add("canary shield install", _c(
    "preview or apply the narrow Sysmon includes and SYSTEM task",
    """Render the exact Sysmon config and task command. Apply requires the
plan id from the dry-run and a reason. The prior Sysmon config is backed up;
uninstall restores it.""",
    [
        ("Preview", "plasma canary shield install"),
        ("Apply", "plasma canary shield install --apply --plan 4 --reason \"pilot\""),
    ],
    safety=PLAN_GATED,
    notes=["The config adds only canary basenames and registry fragments.",
           "Sysmon is reloaded with -c; a rejected config restores the backup."],
    see_also=["canary shield", "canary shield uninstall", "canary shield status"],
))

_add("canary shield uninstall", _c(
    "remove the shield task and restore the prior Sysmon config",
    "Preview or apply removal of the SYSTEM task and restoration of the backed-up Sysmon configuration.",
    [
        ("Preview", "plasma canary shield uninstall"),
        ("Apply", "plasma canary shield uninstall --apply --plan 5 --reason \"change window\""),
    ],
    safety=PLAN_GATED,
    see_also=["canary shield install", "canary shield status"],
))

_add("canary shield sweep", _c(
    "read canary events; dry-run or kill accessing processes",
    """Read Sysmon FileCreate/FileDelete and RegistryEvent rows in the
window, match them against the recorded file/registry canaries, verify the
live process, and either report the plan (default) or kill the process
(`--apply`). Protected and trusted processes are refused and journaled.""",
    [
        ("Dry-run", "plasma canary shield sweep --since-minutes 10"),
        ("Kill", "plasma canary shield sweep --apply --reason \"canary tripped\""),
        ("Narrow window", "plasma canary shield sweep --since-minutes 2 --max-kills 2"),
    ],
    safety=LOCAL_WRITE,
    notes=["A kill requires --reason; the kill switch is also enforced.",
           "The scheduled task runs this with --apply every minute.",
           "Only write/delete/registry events count; reads do not."],
    see_also=["canary shield install", "canary shield status", "actuate actions"],
))

_add("canary registry", _c(
    "decoy registry keys for the active shield",
    "Create, list or remove decoy registry keys that no legitimate software should write. The shield's narrow Sysmon RegistryEvent include watches those keys and can kill the writing process.",
    [
        ("Deploy HKCU key", "plasma canary registry deploy --hive HKCU --count 1"),
        ("List", "plasma canary registry list"),
        ("Remove", "plasma canary registry remove <id>"),
    ],
    safety=LOCAL_WRITE,
    see_also=["canary shield", "canary deploy"],
))

_add("canary registry deploy", _c(
    "create decoy registry keys",
    "Create random keys under Software\\PlasmaDecoy in HKCU or HKLM and record them for the shield.",
    [("One HKCU key", "plasma canary registry deploy --hive HKCU --count 1")],
    safety=LOCAL_WRITE,
    see_also=["canary registry list", "canary shield install"],
))

_add("canary registry list", _c(
    "list decoy registry keys",
    "List the recorded registry canaries and their key fragments.",
    [("List", "plasma canary registry list")],
    safety=READ_ONLY,
    see_also=["canary registry deploy", "canary shield status"],
))

_add("canary registry remove", _c(
    "remove a decoy registry key",
    "Delete the recorded key and remove it from the registry canary file.",
    [("Remove", "plasma canary registry remove 1a2b3c4d5e6f")],
    safety=LOCAL_WRITE,
    see_also=["canary registry list"],
))

_add("canary pipe", _c(
    "named-pipe canaries that kill the client that connects",
    """Deploy a randomly named decoy named pipe and run a listener. Nothing
legitimate should connect to it; a client that does is identified with
GetNamedPipeClientProcessId, verified, and killed unless it is protected or
trusted.

Enumeration alone is not a connection and is not killed. The listener is a
user-mode SYSTEM task, not a kernel driver. Reads/writes over the pipe are
not needed: the connection itself is the tripwire.""",
    [
        ("Deploy", "plasma canary pipe deploy --count 1"),
        ("Preview task", "plasma canary pipe install"),
        ("Arm", "plasma canary pipe install --apply --plan 3 --reason \"IR-42\""),
        ("Run a bounded test", "plasma canary pipe serve --apply --reason \"drill\" --max-connections 1"),
        ("Status", "plasma canary pipe status"),
    ],
    safety=PLAN_GATED,
    notes=["Windows only; the listener blocks while running.",
           "A scanner that enumerates pipes is not touched; a client that connects is.",
           "Protected processes are refused; Plasma/Defender/backup are trusted."],
    see_also=["canary pipe deploy", "canary pipe serve", "canary shield status"],
))

_add("canary pipe deploy", _c(
    "create decoy named-pipe names",
    "Create random, plausible pipe names and record them for the listener.",
    [("One pipe", "plasma canary pipe deploy --count 1")],
    safety=LOCAL_WRITE,
    see_also=["canary pipe list", "canary pipe install"],
))

_add("canary pipe list", _c(
    "list decoy pipes",
    "Show the recorded pipe names and paths.",
    [("List", "plasma canary pipe list")],
    safety=READ_ONLY,
    see_also=["canary pipe deploy"],
))

_add("canary pipe remove", _c(
    "remove a decoy pipe",
    "Remove one pipe from the registry; the listener picks it up on restart.",
    [("Remove", "plasma canary pipe remove 1a2b3c4d5e6f")],
    safety=LOCAL_WRITE,
    see_also=["canary pipe list"],
))

_add("canary pipe serve", _c(
    "listen on decoy pipes and kill connecting processes",
    """Block and listen on every deployed pipe. On a connection, get the
client PID, verify the live image, refuse protected/trusted processes, and
kill unless the listener is in dry-run mode. The connection is also written
to the event store and the pipe journal.""",
    [
        ("Bounded dry-run", "plasma canary pipe serve --max-connections 1"),
        ("Bounded kill", "plasma canary pipe serve --apply --reason \"drill\" --max-connections 1"),
        ("Run until stopped", "plasma canary pipe serve --apply --reason \"scheduled\""),
    ],
    safety=LOCAL_WRITE,
    notes=["Blocks by design; the installed task runs it at startup.",
           "A --reason is mandatory with --apply.",
           "The listener is user-mode; remote access depends on SMB/pipe ACLs."],
    see_also=["canary pipe install", "canary pipe status"],
))

_add("canary pipe install", _c(
    "preview/apply the SYSTEM pipe listener task",
    "Preview or register a SYSTEM task that starts the pipe listener at boot and restarts it on failure.",
    [
        ("Preview", "plasma canary pipe install"),
        ("Apply", "plasma canary pipe install --apply --plan 3 --reason \"pilot\""),
    ],
    safety=PLAN_GATED,
    see_also=["canary pipe serve", "canary pipe uninstall"],
))

_add("canary pipe uninstall", _c(
    "remove the pipe listener task",
    "Preview or stop and unregister the SYSTEM task.",
    [
        ("Preview", "plasma canary pipe uninstall"),
        ("Apply", "plasma canary pipe uninstall --apply --plan 4 --reason \"change window\""),
    ],
    safety=PLAN_GATED,
    see_also=["canary pipe install"],
))

_add("canary pipe status", _c(
    "pipe task and last listener state",
    "Report task state, pipe count, last connections and last kills.",
    [("Status", "plasma canary pipe status")],
    safety=READ_ONLY,
    see_also=["canary pipe install", "canary pipe serve"],
))

# END_OF_HELP_SOURCE
