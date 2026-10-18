# Plasma frozen instance

A neuralOS instance over normalized endpoint events. The menu routes plain
English to ten read-only probes; the bridge executes them against the local
event store. The instance is frozen: `models.py`, `needle_menu.json`,
`graph_edges.json`, `bridge.py`, `bridge.ps1`, `graph_bridge.py`.

## Probes

| Probe | Answers |
|---|---|
| `plasma_overview` | totals, severity/kind/host breakdown, techniques |
| `plasma_recent` | newest events, optionally one host |
| `plasma_alerts` | Sentinel detections by severity / technique |
| `plasma_processes` | process + image-load events, filter by host/process/user |
| `plasma_network` | outbound connections, filter by IP/port |
| `plasma_dns` | DNS lookups grouped by query |
| `plasma_persistence` | registry / Run-key / IFEO / scheduled-task indicators |
| `plasma_search` | free-text search across command lines and paths |
| `plasma_graph_overview` | entity/edge overview of the relationship layer |
| `plasma_graph_neighbors` | one-hop neighbors of a host/process/user/IP/domain |

## Runtime

* **Windows with Python:** `python bridge.py --tool ... --args '{...}'`
* **Windows without Python:** `pwsh -File bridge.ps1 -Tool ... -ArgsJson '{...}'`
* **Selection engine:** `needle.exe --model needle3.cact --tools needle_menu.json --prompt "..."`

The event store is resolved from `PLASMA_EVENTS`, then `./events.jsonl`, then
the packaged samples, then `C:\ProgramData\Plasma\data\events.jsonl`.

## Contract

Read-only probes only. Results are capped at 25 rows plus counts. Every record
is shape-checked (`PlasmaEvent` at build time; generated validators on the
PowerShell surface). Errors are data. Response actions belong to Sentinel's
deterministic policy layer, never to the model.
