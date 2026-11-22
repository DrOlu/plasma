#!/usr/bin/env python3
"""Sample Plasma sensor: emit bounded NDJSON events on stdout."""
import json
import os
import sys
import time


def main() -> int:
    limit = int(os.environ.get("PLASMA_PLUGIN_MAX_EVENTS", "10"))
    for index in range(limit):
        sys.stdout.write(json.dumps({
            "v": 1, "type": "event", "plugin": "sample-sensor", "seq": index,
            "event": {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": "process", "process": "sample-sensor.exe",
                "parent": "explorer.exe", "user": "CORP\\sample",
                "pid": 4000 + index, "score": 0.1,
                "description": "sample plugin event"
            }
        }) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
