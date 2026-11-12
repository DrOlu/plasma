# FAQ

### Is Plasma an EDR?

Functionally yes — endpoint detection and response with sensors, scoring,
correlation and containment. Architecturally it deliberately drops the
central lake and the always-on vendor console, and it refuses to put the
model in the action path.

### Why no central log lake?

Because the questions teams actually ask are about *recent, bounded*
history ("what happened on this box in the last hour?"), and shipping every
event to a central store is a large standing cost and a large standing
target. Plasma keeps a bounded local diary and pulls only what a case
needs. When you do need estate-wide correlation, `fleet` joins bounded
tails on the desk.

### What is actually different from SIEM/SOAR?

| | SIEM | SOAR | Plasma |
|---|---|---|---|
| Data | central lake | orchestrates other tools | bounded local diary per box |
| Detection | correlation rules in the lake | playbooks trigger on alerts | written rules + chains over local events |
| Response | tickets | automation with credentials | named, dry-run-first, journaled, undoable actions |
| Model | vendor AI in the cloud | n/a | 121M on-device router over a closed probe menu |

### Can it block or kill automatically?

No. Every mutation requires a human passing `--apply --plan <id>` from a
seen dry-run. Detection is automatic; response is not.

### Does the AI decide anything?

It selects a **probe** from a fixed menu and fills arguments; it cannot
invent tools, read raw logs, or run commands. Detection and correlation are
deterministic code.

### Can it run fully offline?

Yes. With internet, the installer provisions Sysmon automatically. Without
it, the install degrades to MINIMAL mode (identity + tap) and everything
else works from local data.

### Does it phone home?

No. There is no Plasma cloud service. Update checks are explicit commands
against GitHub releases.

### How many hosts can a desk manage?

`fleet` is bounded by your WinRM reachability and the desk's patience, not
by a license. Each pull takes a capped tail per host (default 300 rows).

### What about Linux/macOS hosts?

Plasma targets Windows endpoints. The fleet desk runs on macOS/Linux
(WinRM client). A Linux sensor is a separate roadmap item.

### Where are credentials stored?

Never in Plasma configs. Inventory uses `password_env`; notify uses
`token_env`; inline secrets are refused. The desk environment (or your
secret manager) holds the values.

### Is the model fine-tunable for my estate?

The supported adaptation is the **probe menu**, not the weights: add a
probe, run the gap loop, re-export the menu, redeploy the same bundle.
Weight fine-tuning of the tiny router is not shipped as a supported path.

### Is Plasma signed?

Releases are Authenticode-signed by the project certificate, and update
applies are verified against pinned signer thumbprints. Publicly trusted
signing (SignPath Foundation) is applied for; SmartScreen reputation builds
after approval.

### Is it open source?

MIT. Repository: [DrOlu/plasma](https://github.com/DrOlu/plasma).

### How do I report a security issue?

Open a GitHub issue for non-sensitive reports. For sensitive ones, contact
the maintainer through the address on the repository profile rather than
posting details publicly.
