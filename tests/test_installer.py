import json
import shutil
import subprocess

import pytest

from plasma.bundle import build_bundle

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")


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
