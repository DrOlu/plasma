"""The installer must converge an existing WHIDS install from the bundle.

Field regression (v1.5.0 estate): a node kept running whatever config.toml
was on disk — WS1 had Whids' default 6.7 KB config and crash-looped every
five seconds, WS2 had a pre-1.4 Plasma config with `channels = ["all"]`.
"""

from plasma.cli import _same_bytes, _whids_files_to_stage
from plasma import whids


def make_bundle(tmp_path):
    whids_dir = tmp_path / "bundle" / "sensors" / "whids"
    whids_dir.mkdir(parents=True)
    (whids_dir / "whids.toml").write_text("# current Plasma config\n")
    (whids_dir / "plasma-iocs.gen").write_text('{"Name":"iocs"}\n')
    (whids_dir / "plasma-baseline.gen").write_text('{"Name":"baseline"}\n')
    (whids_dir / "LICENSE").write_text("MIT\n")
    exe = tmp_path / "runtime" / "whids.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ")
    return whids_dir, exe


def test_stage_map_rewrites_a_stale_config(tmp_path):
    whids_dir, exe = make_bundle(tmp_path)
    install = tmp_path / "Program Files" / "Whids"
    (install / "Database" / "Rules").mkdir(parents=True)
    (install / "config.toml").write_text('channels = ["all"]\n')  # stale

    wanted = _whids_files_to_stage(install, whids_dir, exe)

    assert wanted[install / "config.toml"] == whids_dir / "whids.toml"
    assert wanted[install / "whids.toml"] == whids_dir / "whids.toml"
    assert wanted[install / "whids.exe"] == exe
    rules = install / "Database" / "Rules"
    assert wanted[rules / "plasma-baseline.gen"] == whids_dir / "plasma-baseline.gen"
    assert wanted[rules / "plasma-iocs.gen"] == whids_dir / "plasma-iocs.gen"
    assert _same_bytes(install / "config.toml", whids_dir / "whids.toml") is False


def test_stage_map_requires_no_existing_install(tmp_path):
    whids_dir, exe = make_bundle(tmp_path)
    install = tmp_path / "fresh" / "Whids"
    wanted = _whids_files_to_stage(install, whids_dir, exe)
    assert (install / "config.toml") in wanted
    rules = install / "Database" / "Rules"
    assert sorted(p.name for p in wanted if p.parent == rules) == [
        "plasma-baseline.gen", "plasma-iocs.gen"]


def test_same_bytes_detects_identical_changed_and_missing(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("x")
    b.write_text("x")
    assert _same_bytes(a, b)
    b.write_text("y")
    assert not _same_bytes(a, b)
    assert not _same_bytes(a, tmp_path / "missing")


def test_deploy_rules_removes_obsolete_backups(tmp_path):
    """Gene loads every *.gen, including old timestamped backups."""
    src = tmp_path / "sensors"
    src.mkdir()
    (src / "plasma-baseline.gen").write_text('{"Name":"baseline"}\n')
    (src / "plasma-iocs.gen").write_text('{"Name":"iocs"}\n')
    db = tmp_path / "rules"
    db.mkdir()
    stale = db / "plasma-iocs.20261019T114428Z.bak.gen"
    stale.write_text('{"Name":"old"}\n')

    copied = whids.deploy_rules(src, db)

    assert copied == ["plasma-iocs.gen", "plasma-baseline.gen"]
    assert not stale.exists()
    assert sorted(p.name for p in db.glob("*.gen")) == [
        "plasma-baseline.gen", "plasma-iocs.gen"]
