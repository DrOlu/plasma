#!/usr/bin/env python3
"""Sample Plasma detector: read events, print NDJSON findings."""
import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True)
    parser.add_argument("--since", default=None)
    parser.add_argument("--max-rows", type=int, default=1000)
    args = parser.parse_args()
    watched = {"mimikatz.exe", "psexec.exe"}
    with open(args.events, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle.readlines()[-args.max_rows:]:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(row.get("process") or "").lower() in watched:
                print(json.dumps({
                    "v": 1, "type": "finding", "plugin": "sample-detector",
                    "finding": {
                        "description": "sample detector: watched process "
                                       + str(row.get("process")),
                        "score": 0.8, "technique": "T1059",
                        "evidence": [str(row.get("ts")),
                                     str(row.get("process"))]
                    }
                }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
