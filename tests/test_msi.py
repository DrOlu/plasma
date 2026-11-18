"""MSI generator: the WiX source must be well-formed and complete."""
import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

NS = "{http://wixtoolset.org/schemas/v4/wxs}"
TOOL = Path(__file__).resolve().parent.parent / "tools" / "build_msi.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_msi", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _exe(tmp_path):
    exe = tmp_path / "plasma-1.4.0-windows-x64.exe"
    exe.write_bytes(b"MZ fake")
    return exe


def test_wxs_is_wellformed_and_complete(tmp_path):
    mod = _load()
    exe = _exe(tmp_path)
    root = ET.fromstring(mod.build_wxs(exe, "1.4.0"))
    assert root.tag == f"{NS}Wix"
    pkg = root.find(f"{NS}Package")
    assert pkg is not None
    assert pkg.get("Version") == "1.4.0"
    assert pkg.get("Scope") == "perMachine"
    assert pkg.get("UpgradeCode") == mod.UPGRADE_CODE
    assert pkg.get("InstallerVersion") == "500"
    assert pkg.get("Platform") is None  # WiX v5 uses -arch x64, not Package/@Platform

    prop = root.find(f"{NS}Package/{NS}Property")
    assert prop.get("Id") == "PLASMA_ROOT"

    f = root.find(f".//{NS}File")
    assert f is not None and f.get("Source") == str(exe)

    ca = root.find(f".//{NS}CustomAction")
    assert ca is not None
    assert ca.get("Execute") == "deferred"
    assert ca.get("Impersonate") == "no"
    assert "install --force --root" in ca.get("ExeCommand")
    assert "[PLASMA_ROOT]" in ca.get("ExeCommand")
    # The package must leave the running node on the packaged version, not
    # just copy a versioned sibling: --rotate swaps bin\plasma.exe and
    # restarts the tasks.
    assert "--rotate" in ca.get("ExeCommand")

    seq = root.find(f".//{NS}Custom")
    assert seq.get("Action") == ca.get("Id")
    assert seq.get("Condition") == "NOT REMOVE"

    assert root.find(f".//{NS}MajorUpgrade") is not None


def test_bad_versions_rejected(tmp_path):
    mod = _load()
    exe = _exe(tmp_path)
    for bad in ("1.4", "v1.4.0", "1.4.0-rc1"):
        with pytest.raises(SystemExit):
            mod.build_wxs(exe, bad)


def test_missing_exe_rejected(tmp_path):
    mod = _load()
    with pytest.raises(SystemExit):
        mod.build_wxs(tmp_path / "nope.exe", "1.4.0")


def test_wxs_only_mode(tmp_path, capsys):
    mod = _load()
    exe = _exe(tmp_path)
    out = tmp_path / "dist" / "plasma-1.4.0-windows-x64.msi"
    rc = mod.main(["--exe", str(exe), "--version", "1.4.0",
                   "--out", str(out), "--wxs-only"])
    assert rc == 0
    wxs = out.with_suffix(".wxs")
    assert wxs.exists() and not out.exists()
    assert "UpgradeCode" in wxs.read_text()


def test_build_passes_x64_arch(tmp_path, monkeypatch):
    mod = _load()
    exe = _exe(tmp_path)
    out = tmp_path / "dist" / "plasma-1.4.0-windows-x64.msi"
    seen = []

    class _Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        seen.append(cmd)
        out.write_bytes(b"fake msi")
        return _Done()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    rc = mod.main(["--exe", str(exe), "--version", "1.4.0",
                   "--out", str(out)])
    assert rc == 0
    assert seen and "-arch" in seen[0] and "x64" in seen[0]
