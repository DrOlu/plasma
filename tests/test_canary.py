"""Canary files: impact detection via decoys (T1486)."""
import json
from pathlib import Path

from plasma import canary, health, watch


def _deploy(tmp_path):
    root = tmp_path / "plasma"
    result = canary.deploy(root)
    return root, result


def test_deploy_writes_files_and_manifest(tmp_path):
    root, result = _deploy(tmp_path)
    assert result["deployed"] == len(canary.CANARY_NAMES)
    assert result["created"] == len(canary.CANARY_NAMES)
    manifest = json.loads((root / "canaries.json").read_text())
    assert len(manifest["canaries"]) == len(canary.CANARY_NAMES)
    for entry in manifest["canaries"]:
        assert Path(entry["path"]).exists()
        assert len(entry["sha256"]) == 64


def test_deploy_extra_dirs(tmp_path):
    root, _ = _deploy(tmp_path)
    extra = tmp_path / "finance"
    canary.deploy(root, extra_dirs=[extra])
    assert (extra / canary.CANARY_NAMES[0]).exists()
    manifest = json.loads((root / "canaries.json").read_text())
    paths = [e["path"] for e in manifest["canaries"]]
    assert any(str(extra) in p for p in paths)


def test_deploy_does_not_overwrite_existing(tmp_path):
    root = tmp_path / "plasma"
    target = canary.default_dir(root) / canary.CANARY_NAMES[0]
    target.parent.mkdir(parents=True)
    target.write_text("pre-existing content")
    result = canary.deploy(root)
    assert target.read_text() == "pre-existing content"
    assert result["created"] == len(canary.CANARY_NAMES) - 1
    # the manifest records the hash of what is actually there
    assert canary.verify(root)["intact"] == len(canary.CANARY_NAMES)


def test_verify_intact(tmp_path):
    root, _ = _deploy(tmp_path)
    result = canary.verify(root)
    assert result["checked"] == len(canary.CANARY_NAMES)
    assert result["intact"] == len(canary.CANARY_NAMES)
    assert result["tripped"] == [] and result["top_score"] == 0


def test_verify_detects_deletion(tmp_path):
    root, _ = _deploy(tmp_path)
    victim = Path(json.loads((root / "canaries.json").read_text())
                  ["canaries"][0]["path"])
    victim.unlink()
    result = canary.verify(root)
    assert result["top_score"] == 10
    assert result["tripped"] == [{"path": str(victim), "reason": "missing"}]


def test_verify_detects_modification(tmp_path):
    root, _ = _deploy(tmp_path)
    victim = Path(json.loads((root / "canaries.json").read_text())
                  ["canaries"][1]["path"])
    victim.write_text("encrypted by ransomware")
    result = canary.verify(root)
    assert result["top_score"] == 10
    assert result["tripped"][0]["reason"] == "modified"


def test_verify_without_manifest_is_error(tmp_path):
    result = canary.verify(tmp_path / "nothing")
    assert "error" in result and result["checked"] == 0


def test_status(tmp_path):
    root, _ = _deploy(tmp_path)
    st = canary.status(root)
    assert st["deployed"] is True
    assert st["canaries"] == len(canary.CANARY_NAMES)
    assert st["intact"] == len(canary.CANARY_NAMES) and st["tripped"] == []


def test_watch_sweep_surfaces_tripped_canaries(tmp_path, monkeypatch):
    root = tmp_path / "plasma"
    (root).mkdir(parents=True)
    (root / "config.json").write_text(json.dumps({
        "events_path": str(root / "e.jsonl"), "degraded": True,
        "sensors": {"whids": {"status": "skipped"}}}))
    canary.deploy(root)
    Path(json.loads((root / "canaries.json").read_text())
         ["canaries"][0]["path"]).unlink()
    monkeypatch.setattr(health, "verdict",
                        lambda r: {"status": "ok", "failed": [], "checks": []})
    monkeypatch.setattr(watch.observatory, "run_question",
                        lambda q, **k: {"question": q, "blind_count": 0})
    monkeypatch.setattr("plasma.drift.load", lambda root, name: None)
    res = watch.sweep(root)
    hits = [f for f in res["findings"] if f["type"] == "canary_tripped"]
    assert hits and hits[0]["score"] == 10
    assert res["verdict"] == "act now"
