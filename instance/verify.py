#!/usr/bin/env python3
"""Phase-4 verification: model coverage + selection test.

    python verify.py            # fetch a sample, then report coverage
    python verify.py --full     # also run a 3-phrasing selection test
"""
import json
import os
import subprocess
import sys

import bridge

SAMPLE_CALL = lambda: bridge.peek(limit=10)   # executed, not printed
PHRASINGS = ['how many records', 'count records', 'record count']


def fetch_sample():
    print("== fetching a sample through the bridge ==")
    result = SAMPLE_CALL()
    print(json.dumps(result, ensure_ascii=False, default=str)[:400])


def coverage():
    print("== model coverage ==")
    v = getattr(bridge, "_VALIDATION", {})
    print(json.dumps(v, indent=2))
    total = v.get("parsed", 0) + v.get("failed", 0)
    if total:
        print("coverage: %.1f%% (%d/%d records parsed cleanly)"
              % (100 * v["parsed"] / total, v["parsed"], total))
    else:
        print("coverage: no records parsed yet — fetch_sample above must have failed; "
              "check the bridge error output")


def selection():
    print("== selection test (3 phrasings) ==")
    if not os.path.exists("instance.py"):
        print("(engine runtime: no instance.py generated — run the engine binary "
              "with needle_menu.json and the same phrasings instead)")
        return
    for phrasing in PHRASINGS:
        out = subprocess.run([sys.executable, "instance.py", phrasing],
                             capture_output=True, text=True)
        for line in out.stdout.splitlines():
            if line.startswith("reasoning") or line.startswith("result"):
                print(f"  [{phrasing!r}] {line[:160]}")


def truth():
    print("== truth oracle: probe vs direct SQL (numeric-aware) ==")
    import os
    if not os.path.exists("truth.json"):
        print("(no truth.json — file-kind instance: nothing to cross-check)")
        return
    items = json.load(open("truth.json", encoding="utf-8"))
    ok_all = True
    for t in items:
        via_sql = bridge._q(t["sql"])
        if via_sql and "error" in via_sql[0]:
            print(f"FAIL  {t['id']}: {via_sql[0]['error']}"); ok_all = False; continue
        sql_val = list(via_sql[0].values())[0]
        probe_fn = getattr(bridge, t["probe"], None)
        probe_res = probe_fn() if probe_fn else {}
        probe_val = probe_res.get("count", probe_res.get("returned"))
        try:
            same = float(probe_val) == float(sql_val)
        except (TypeError, ValueError):
            same = str(probe_val) == str(sql_val)
        print(f"{'PASS' if same else 'FAIL'}  {t['id']}: probe={probe_val} sql={sql_val}")
        ok_all &= same
    if not ok_all:
        raise SystemExit(1)


def golden():
    print("== golden question bank (through ask.py) ==")
    bank = json.load(open("golden.json", encoding="utf-8"))
    bad = 0
    for item in bank["items"]:
        out = subprocess.run([sys.executable, "ask.py", item["q"]],
                             capture_output=True, text=True)
        try:
            env = json.loads(out.stdout)
            probe = env.get("probe") or (env[0].get("_tool") if isinstance(env, list) and env else None)
        except Exception:
            probe = None
        ok = out.returncode == 0 and (item["expect_probe"] is None or probe == item["expect_probe"])
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {item['q']!r} -> probe={probe}")


if __name__ == "__main__":
    fetch_sample()
    coverage()
    if "--full" in sys.argv or "--selection" in sys.argv:
        selection()
    if "--truth" in sys.argv:
        truth()
    if "--golden" in sys.argv:
        golden()
    if "--invariants" in sys.argv:
        import subprocess
        r = subprocess.run([sys.executable, "invariants.py"])
        raise SystemExit(r.returncode)
