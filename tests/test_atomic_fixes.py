"""Regression tests for the fixes driven by the Atomic Red Team estate run."""
from __future__ import annotations

import json
from pathlib import Path

from plasma import whids

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "sensors" / "plasma-baseline.gen"


def _rule(name: str) -> dict:
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row["Name"] == name:
                return row
    raise AssertionError(f"missing rule {name}")


def _event(target: str, image: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
    return {"Image": image, "TargetFilename": target}


def test_psscriptpolicytest_is_suppressed_for_public_folder_noise():
    event = _event(r"C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_abc.ps1")
    assert whids._benign_context(
        "Sigma: Suspicious Binaries and Scripts in Public Folder", event)
    assert whids._benign_context(
        "Sigma: Suspicious File Write to SharePoint Layouts Directory", event)


def test_psscriptpolicytest_does_not_suppress_unrelated_files():
    event = _event(r"C:\Users\Public\evil.ps1")
    assert whids._benign_context(
        "Sigma: Suspicious Binaries and Scripts in Public Folder", event) is None


def test_atomic_smoke_manifest_is_complete():
    manifest = json.loads((REPO / "sensors" / "atomic-smoke.json").read_text())
    cases = manifest["cases"]
    assert manifest["version"] == 1
    assert len(cases) == 6
    guids = [c["guid"] for c in cases]
    assert len(set(guids)) == len(guids)
    names = {r["Name"] for r in map(json.loads, BASELINE.read_text().splitlines()) if r}
    for case in cases:
        assert case["technique"].startswith("T")
        assert case["expected_rule"] in names, case
