import platform

import pytest

import plasma.cli as cli


def test_embedded_instance_dir(monkeypatch, tmp_path):
    inst = tmp_path / "embedded" / "instance"
    inst.mkdir(parents=True)
    monkeypatch.setattr(cli.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert cli._instance_dir(None) == inst
    assert cli._instance_dir("embedded") == inst
    assert cli._instance_dir(str(tmp_path / "bundle")) == tmp_path / "bundle" / "instance"


def test_embedded_engine_and_model_resolution(monkeypatch, tmp_path):
    platform_name = cli._current_platform()
    engines = tmp_path / "embedded" / "engines" / platform_name
    engines.mkdir(parents=True)
    for name in ("needle", "needle.exe"):
        (engines / name).write_bytes(b"engine")
    (engines / "needle3.cact").write_bytes(b"weights")
    monkeypatch.setattr(cli.sys, "_MEIPASS", str(tmp_path), raising=False)

    found_engine = cli._find_engine(None, None)
    assert found_engine is not None
    assert found_engine.parent == engines
    assert cli._find_model(None, found_engine, None) == engines / "needle3.cact"


def test_gzipped_engine_is_materialized(monkeypatch, tmp_path):
    import gzip

    platform_name = cli._current_platform()
    engines = tmp_path / "embedded" / "engines" / platform_name
    engines.mkdir(parents=True)
    with gzip.open(engines / "needle.gz", "wb") as fh:
        fh.write(b"fake-engine-bytes")
    (engines / "needle3.cact").write_bytes(b"weights")
    monkeypatch.setattr(cli.sys, "_MEIPASS", str(tmp_path), raising=False)

    found = cli._find_engine(None, None)
    assert found is not None
    assert found.read_bytes() == b"fake-engine-bytes"
    assert found.parent.name == "plasma-runtime"


def test_embedded_root_absent_without_meipass(monkeypatch):
    monkeypatch.delattr(cli.sys, "_MEIPASS", raising=False)
    assert cli._embedded_root() is None
    # Developer fallback resolves to the repo instance directory.
    assert (cli._instance_dir(None) / "needle_menu.json").exists()


@pytest.mark.skipif(platform.system() == "Windows", reason="Windows-only guard test")
def test_install_refuses_non_windows(capsys):
    code = cli.main(["install", "--dry-run"])
    assert code == 2
    assert "Windows-only" in capsys.readouterr().out
