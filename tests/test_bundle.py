import json
import zipfile

import pytest

from plasma.bundle import build_bundle
from plasma.manifest import verify_manifest


def test_build_bundle(tmp_path):
    result = build_bundle(tmp_path / "dist", "0.5.0")
    assert result["ok"] is True
    assert result["probes"] == 10
    stage = tmp_path / "dist" / "plasma-0.5.0"
    for rel in [
        "instance/needle_menu.json", "instance/models.py", "instance/bridge.py",
        "instance/bridge.ps1", "instance/graph_edges.json",
        "packaging/install.ps1", "packaging/verify.ps1",
        "sensors/whids.pin.json", "docs/ARCHITECTURE.md", "README.md", "LICENSE",
    ]:
        assert (stage / rel).exists(), rel
    assert verify_manifest(stage)["ok"] is True


def test_bundle_zip(tmp_path):
    result = build_bundle(tmp_path / "dist", "0.5.0")
    zpath = tmp_path / "dist" / "plasma-0.5.0.zip"
    assert zpath.exists()
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
    assert any(n.endswith("manifest.json") for n in names)
    assert any(n.endswith("instance/needle_menu.json") for n in names)


def test_bundle_refuses_overwrite(tmp_path):
    build_bundle(tmp_path / "dist", "0.5.0")
    with pytest.raises(FileExistsError):
        build_bundle(tmp_path / "dist", "0.5.0")


def test_manifest_records_sensor_requirements(tmp_path):
    build_bundle(tmp_path / "dist", "0.5.0")
    manifest = json.loads((tmp_path / "dist" / "plasma-0.5.0" / "manifest.json").read_text())
    assert manifest["sensor_requirements"]["whids"]["required"] is True
    assert manifest["sensor_requirements"]["sysmon"]["required"] is True
    assert manifest["sensor_requirements"]["sealighter"]["required"] is False
    assert manifest["instance"]["probes"] == 10


def test_bundle_includes_whids_payload_and_binary(tmp_path):
    payload = tmp_path / "whids-payload"
    payload.mkdir()
    (payload / "whids.exe").write_bytes(b"fake-whids-binary")
    (payload / "LICENSE").write_text("AGPL-3.0", encoding="utf-8")
    binary = tmp_path / "plasma.exe"
    binary.write_bytes(b"\x4d\x5a fake")

    result = build_bundle(
        tmp_path / "dist", "0.5.0",
        whids_payload=payload, binaries=[binary],
    )
    stage = tmp_path / "dist" / "plasma-0.5.0"
    assert result["whids_payload_files"] == 2
    assert result["binaries"] == ["plasma.exe"]
    assert (stage / "sensors/whids/whids.exe").exists()
    assert (stage / "sensors/whids/LICENSE").exists()
    assert (stage / "bin/plasma.exe").exists()
    assert verify_manifest(stage)["ok"] is True


def test_sentinel_pin_absent(tmp_path):
    build_bundle(tmp_path / "dist", "0.5.0")
    stage = tmp_path / "dist" / "plasma-0.5.0"
    assert not (stage / "sensors/sentinel.pin.json").exists()
