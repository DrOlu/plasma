import json
import zipfile

import pytest

from plasma.bundle import build_bundle
from plasma.manifest import verify_manifest


def test_build_bundle(tmp_path):
    result = build_bundle(tmp_path / "dist", "0.1.0")
    assert result["ok"] is True
    assert result["probes"] == 10
    stage = tmp_path / "dist" / "plasma-0.1.0"
    for rel in [
        "instance/needle_menu.json", "instance/models.py", "instance/bridge.py",
        "instance/bridge.ps1", "instance/graph_edges.json",
        "packaging/install.ps1", "packaging/verify.ps1",
        "sensors/sentinel.pin.json", "docs/ARCHITECTURE.md", "README.md", "LICENSE",
    ]:
        assert (stage / rel).exists(), rel
    assert verify_manifest(stage)["ok"] is True


def test_bundle_zip(tmp_path):
    result = build_bundle(tmp_path / "dist", "0.1.0")
    zpath = tmp_path / "dist" / "plasma-0.1.0.zip"
    assert zpath.exists()
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
    assert any(n.endswith("manifest.json") for n in names)
    assert any(n.endswith("instance/needle_menu.json") for n in names)


def test_bundle_refuses_overwrite(tmp_path):
    build_bundle(tmp_path / "dist", "0.1.0")
    with pytest.raises(FileExistsError):
        build_bundle(tmp_path / "dist", "0.1.0")


def test_manifest_records_sensor_requirements(tmp_path):
    build_bundle(tmp_path / "dist", "0.1.0")
    manifest = json.loads((tmp_path / "dist" / "plasma-0.1.0" / "manifest.json").read_text())
    assert manifest["sensor_requirements"]["sentinel"]["required"] is True
    assert manifest["sensor_requirements"]["sysmon"]["required"] is False
    assert manifest["instance"]["probes"] == 10


def test_bundle_includes_sentinel_payload_and_binary(tmp_path):
    payload = tmp_path / "sentinel-payload"
    payload.mkdir()
    (payload / "SentinelSetup-9.9.9.exe").write_bytes(b"fake-setup")
    (payload / "LICENSE").write_text("MIT", encoding="utf-8")
    (payload / "SHA256SUMS.txt").write_text("hash  SentinelSetup-9.9.9.exe\n", encoding="utf-8")
    binary = tmp_path / "plasma"
    binary.write_bytes(b"\x7fELF fake")

    result = build_bundle(
        tmp_path / "dist", "0.1.0",
        sentinel_payload=payload, binaries=[binary],
    )
    stage = tmp_path / "dist" / "plasma-0.1.0"
    assert result["sentinel_payload_files"] == 3
    assert result["binaries"] == ["plasma"]
    assert (stage / "sensors/sentinel/SentinelSetup-9.9.9.exe").exists()
    assert (stage / "sensors/sentinel/LICENSE").exists()
    assert (stage / "bin/plasma").exists()
    assert verify_manifest(stage)["ok"] is True


def test_sentinel_pin_payload_hash():
    from pathlib import Path
    from plasma.manifest import sha256_file

    root = Path(__file__).resolve().parent.parent
    pin_path = root / "sensors/sentinel.pin.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    payload = pin_path.parent / "sentinel" / pin["payload"]["file"]
    if not payload.exists():
        pytest.skip("Sentinel payload not fetched")
    assert sha256_file(payload) == pin["payload"]["sha256"]
    assert pin["version"] == "3.3.1"
