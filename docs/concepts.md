# Concepts

## The lake-less model

A traditional EDR/SIEM moves raw events to a central store, then queries
there. Plasma inverts the direction: **the box keeps its own diary, and the
desk asks questions when there is a reason to.**

```text
        ┌──────────────────────────── one Windows host ───────────────────────────┐
        │  Sysmon ─┐                                                              │
        │  WHIDS  ─┼─► normalizers ─► data\events.jsonl   (one strict contract)   │
        │  identity┘                        │                                     │
        │  ETW tap (on demand)              ▼                                     │
        │                       frozen neuralOS instance                          │
        │                       (menu of 10 probes, refuses unknowns)             │
        └───────────────────────────────┬─────────────────────────────────────────┘
                                        │  pull over WinRM / SSM
                                        ▼
        desk: status · ask · health · watch · drift · chains · coverage
              fleet pull/correlate/report · actuate (plan-gated)
```

Nothing streams to a server. There is no collector daemon of Plasma's own,
no cloud dependency, and no standing network path except the management
channel you already have (WinRM 5985 or SSM).

## The event contract

Every sensor output is rewritten into the same row shape before it reaches
the store. One shape means every later layer — the brain, chains, fleet,
drift — speaks one language.

```json
{
  "ts": "2026-11-12T10:01:30.000Z",
  "host": "EC2AMAZ-8NK9FUP",
  "source": "plasma",
  "kind": "auth",
  "event_id": 4625,
  "severity": "medium",
  "score": 0.5,
  "action": "logged",
  "user": "CORP\\bob",
  "process": "svchost.exe",
  "pid": 812,
  "dest_ip": "203.0.113.9",
  "description": "logon FAILED type=3 from=203.0.113.9 workstation=WS12"
}
```

Rules the contract enforces:

- **`ts` is UTC.** Collectors convert at the source (`ToUniversalTime()`);
  offset-less rows are treated as UTC on read. Mixed local/UTC timestamps
  would silently break cross-host correlation — this is tested.
- **Machine accounts (`$`) and empty users are dropped** from identity rows.
- **Scores are 0–10** at the finding layer (`severity` maps to it); raw
  Plasma scores are 0–1 and multiplied by ten where a rule expects the
  WHIDS criticality scale.
- **Deduplication by content hash** on append; repeated pulls are free.

## Sensors vs. probes

Terms used consistently in this documentation:

| Term | Meaning |
|---|---|
| **Sensor** | A collector that produces events (Sysmon, WHIDS, identity pull, ETW tap) |
| **Probe** | A read-only question over existing data (the 10-instance menu, coverage, chains, deep persistence) |
| **Finding** | A scored statement about risk, produced by a rule, chain, drift comparison, or fleet correlation |
| **Action** | A named, reversible mutation of the host (actuate) |
| **Playbook** | A named sequence of actions applied as one plan-gated unit |

## The on-device brain

Plasma embeds a frozen neuralOS instance: a 121M-parameter, ~35 MB,
2-bit-quantized tool-calling model plus a fixed menu of probes.

- The model **selects a probe and fills its arguments**. It cannot invent a
  probe, run shell, or read raw logs directly — every answer comes back
  through the probe's typed schema.
- If a request matches nothing on the menu, the **refusal gate** returns a
  refusal instead of guessing.
- The model is never in the detection path and never in the response path.

This is deliberate: a tiny model that routes to validated tools is an
auditable system; a large model that answers freely is not.

## Determinism and evidence

Plasma's promise is not "clever", it is **explainable**:

- Detection = written rules with technique IDs and fixed scores.
- Chains = written sequences with fixed gap windows.
- Correlations = fixed score tables (lateral hop 9, shared hash 8, …).
- Response = a named action, rendered as the exact payload before it runs.

Every finding can be traced to the rule or correlation that produced it, and
every state change is in the journal.
