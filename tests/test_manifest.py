from pathlib import Path

from plasma.manifest import create_manifest, verify_manifest


def make_bundle(root: Path):
    (root / "instance").mkdir(parents=True)
    (root / "instance" / "needle_menu.json").write_text("[]", encoding="utf-8")
    (root / "instance" / "models.py").write_text("class X: pass\n", encoding="utf-8")
    (root / "README.md").write_text("plasma\n", encoding="utf-8")
    return root


def test_create_and_verify(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    manifest = create_manifest(bundle, "0.1.0", instance_probes=10)
    assert manifest["product"] == "Plasma"
    assert manifest["file_count"] == 3
    assert "instance/needle_menu.json" in manifest["files"]

    result = verify_manifest(bundle)
    assert result["ok"] is True
    assert result["checked"] == 3
    assert result["missing"] == []
    assert result["mismatched"] == []


def test_tamper_detected(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    create_manifest(bundle, "0.1.0")
    (bundle / "instance" / "models.py").write_text("class Evil: pass\n", encoding="utf-8")
    result = verify_manifest(bundle)
    assert result["ok"] is False
    assert result["mismatched"]


def test_missing_file_detected(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    create_manifest(bundle, "0.1.0")
    (bundle / "README.md").unlink()
    result = verify_manifest(bundle)
    assert result["ok"] is False
    assert result["missing"] == ["README.md"]


def test_extra_file_detected(tmp_path):
    bundle = make_bundle(tmp_path / "bundle")
    create_manifest(bundle, "0.1.0")
    (bundle / "injected.dll").write_text("x", encoding="utf-8")
    result = verify_manifest(bundle)
    assert result["ok"] is False
    assert result["extra"] == ["injected.dll"]


def test_missing_manifest(tmp_path):
    result = verify_manifest(tmp_path)
    assert result["ok"] is False
    assert "manifest" in result["error"]
