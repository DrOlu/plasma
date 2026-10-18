import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from plasma.bundle import build_bundle

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
ROOT = Path(__file__).resolve().parent.parent
PAYLOAD = ROOT / "sensors/sentinel/SentinelSetup-3.3.1.exe"


@pytest.fixture()
def bundle(tmp_path):
    build_bundle(tmp_path / "dist", "0.1.0")
    return tmp_path / "dist" / "plasma-0.1.0"


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
    assert plan["version"] == "0.1.0"
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


@pytest.mark.skipif(platform.system() != "Windows", reason="Sentinel installs on Windows")
@pytest.mark.skipif(not PAYLOAD.exists(), reason="Sentinel payload not fetched")
def test_dry_run_plans_bundled_sentinel(tmp_path):
    from plasma.bundle import build_bundle
    build_bundle(tmp_path / "dist", "0.1.0", sentinel_payload=ROOT / "sensors/sentinel")
    bundle = tmp_path / "dist" / "plasma-0.1.0"
    proc = run_install(bundle, tmp_path / "root")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    plan = json.loads(proc.stdout)
    assert plan["dry_run"] is True
    sentinel = [s for s in plan["sensors"] if s["sensor"] == "sentinel"][0]
    assert sentinel["will_install"] is True
    assert any("install Sentinel 3.3.1" in a for a in plan["actions"])
    assert not (tmp_path / "root" / "instances").exists()
