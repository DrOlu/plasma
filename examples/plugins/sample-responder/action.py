#!/usr/bin/env python3
"""Sample Plasma responder: create, verify and remove one file."""
import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: action.py preview|apply|verify|rollback <path>")
        return 2
    mode, path = sys.argv[1], sys.argv[2]
    if mode == "preview":
        print("would create", path)
        return 0
    if mode == "apply":
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("created by sample responder\n")
        return 0
    if mode == "verify":
        return 0 if os.path.isfile(path) else 1
    if mode == "rollback":
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
