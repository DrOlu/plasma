"""Critical-file integrity: baseline, modify/remove/add, missing manifest."""
from pathlib import Path

from plasma import fim


def _setup(tmp_path):
    root = tmp_path / "Plasma"
    root.mkdir()
    watched = tmp_path / "etc"
    watched.mkdir()
    (watched / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (watched / "app.cfg").write_text("key=1\n", encoding="utf-8")
    return root, watched


def test_baseline_records_files_and_verifies_intact(tmp_path):
    root, watched = _setup(tmp_path)
    res = fim.baseline(root, [str(watched / "hosts"), str(watched / "*.cfg")])
    assert res["baselined"] == 2
    report = fim.verify(root)
    assert report["checked"] == 2
    assert report["findings"] == []
    assert report["top_score"] == 0


def test_modified_removed_and_added_are_reported(tmp_path):
    root, watched = _setup(tmp_path)
    fim.baseline(root, [str(watched / "hosts"), str(watched / "*.cfg")])
    (watched / "hosts").write_text("127.0.0.1 evil\n", encoding="utf-8")
    (watched / "app.cfg").unlink()
    (watched / "new.cfg").write_text("key=2\n", encoding="utf-8")

    report = fim.verify(root)
    types = sorted(f["type"] for f in report["findings"])
    assert types == ["fim_added", "fim_modified", "fim_removed"]
    assert report["modified"] == 1 and report["removed"] == 1
    assert report["added"] == 1
    assert report["top_score"] == 8


def test_missing_manifest_is_data_not_a_crash(tmp_path):
    root = tmp_path / "Plasma"
    root.mkdir()
    report = fim.verify(root)
    assert "error" in report
    assert report["findings"] == []
    status = fim.status(root)
    assert status["baselined"] is False


def test_status_after_baseline(tmp_path):
    root, watched = _setup(tmp_path)
    fim.baseline(root, [str(watched / "hosts")])
    status = fim.status(root)
    assert status["baselined"] is True
    assert status["entries"] == 1
    assert status["paths"] == [str(watched / "hosts")]
