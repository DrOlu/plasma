import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from plasma.bundle import build_bundle

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = ROOT / "sensors/whids/whids.exe"


@pytest.fixture()
def bundle(tmp_path):
    build_bundle(tmp_path / "dist", "0.5.0")
    return tmp_path / "dist" / "plasma-0.5.0"


def run_install(bundle, root, *extra):
    cmd = ["pwsh", "-NoProfile", "-File", str(bundle / "packaging" / "install.ps1"),
           "-Bundle", str(bundle), "-InstallRoot", str(root), "-DryRun", "-SkipSensorCheck", *extra]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def test_dry_run_writes_nothing(bundle, tmp_path):
    root = tmp_path / "install-root"
    proc = run_install(bundle, root)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    plan = json.loads(proc.stdout)
    assert plan["ok"] is True
    assert plan["dry_run"] is True
    assert plan["version"] == "0.5.0"
    assert plan["files_verified"] > 10
    assert not (root / "instances").exists()


def test_tampered_bundle_rejected(bundle, tmp_path):
    menu = bundle / "instance" / "needle_menu.json"
    menu.write_text(menu.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    proc = run_install(bundle, tmp_path / "root")
    assert proc.returncode == 2
    result = json.loads(proc.stdout)
    assert result["ok"] is False
    assert result["stage"] == "integrity"
    assert result["mismatched"]


@pytest.mark.skipif(platform.system() != "Windows", reason="WHIDS installs on Windows")
@pytest.mark.skipif(not PAYLOAD.exists(), reason="WHIDS payload not fetched")
def test_dry_run_plans_bundled_whids(tmp_path):
    build_bundle(tmp_path / "dist", "0.5.0", whids_payload=ROOT / "sensors/whids")
    bundle = tmp_path / "dist" / "plasma-0.5.0"
    proc = run_install(bundle, tmp_path / "root")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    plan = json.loads(proc.stdout)
    assert plan["dry_run"] is True
    whids = [s for s in plan["sensors"] if s["sensor"] == "whids"][0]
    assert whids["will_install"] is True
    assert any("install WHIDS from embedded bundle payload" in a for a in plan["actions"])
    assert not (tmp_path / "root" / "instances").exists()
