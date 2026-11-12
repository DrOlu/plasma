"""Pinned engine fetch: the CI build must be reproducible after upstream
removed the per-platform bundles (2026-11-05)."""
import importlib.util
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "fetch_engine.py"


def _load():
    spec = importlib.util.spec_from_file_location("fetch_engine", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pinned_revision_is_full_sha_and_platforms_cover_ci_targets():
    mod = _load()
    assert mod.REPO == "Cactus-Compute/needle3"
    assert len(mod.PINNED_REVISION) == 40 and "-" not in mod.PINNED_REVISION
    assert {"windows-x86_64", "linux-x86_64"} <= set(mod.PLATFORMS)


def test_fetch_copies_files_and_marks_executable(tmp_path, monkeypatch):
    mod = _load()
    remote = {
        "windows-x86_64/needle.exe": b"MZ engine",
        "windows-x86_64/libneedle.a": b"lib",
        "windows-x86_64/needle.h": b"header",
    }
    downloads = []

    class FakeHF:
        @staticmethod
        def list_repo_files(repo, repo_type=None, revision=None):
            assert repo == "Cactus-Compute/needle3"
            assert revision == mod.PINNED_REVISION
            return list(remote) + ["needle3.cact"]

        @staticmethod
        def hf_hub_download(repo_id, filename, repo_type=None, revision=None):
            downloads.append(filename)
            p = tmp_path / "cache" / Path(filename).name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(remote[filename])
            return str(p)

    monkeypatch.setitem(sys.modules, "huggingface_hub", FakeHF)
    dest = tmp_path / "engines" / "windows-x86_64"
    out = mod.fetch("windows-x86_64", dest)
    assert sorted(Path(p).name for p in out) == ["libneedle.a", "needle.exe", "needle.h"]
    assert (dest / "needle.exe").exists()
    assert (dest / "needle.exe").stat().st_mode & 0o111, "engine must be executable"
    # weights are never fetched from the pinned revision (bundled wheel copy)
    assert downloads == ["windows-x86_64/libneedle.a", "windows-x86_64/needle.exe",
                         "windows-x86_64/needle.h"]


def test_unknown_platform_rejected(monkeypatch):
    mod = _load()
    with pytest.raises(SystemExit):
        mod.platform_files("plan9-mips")


def test_missing_remote_folder_is_clear_error(monkeypatch):
    mod = _load()

    class FakeHF:
        @staticmethod
        def list_repo_files(repo, repo_type=None, revision=None):
            return ["needle3.cact"]

        @staticmethod
        def hf_hub_download(**kw):
            raise AssertionError("must not download")

    monkeypatch.setitem(sys.modules, "huggingface_hub", FakeHF)
    with pytest.raises(SystemExit, match="no engine files"):
        mod.platform_files("windows-x86_64")


def test_cli_with_weights(tmp_path, monkeypatch):
    mod = _load()
    files = {"linux-x86_64/needle": b"elf", "linux-x86_64/libneedle.a": b"a",
             "linux-x86_64/needle.h": b"h", "needle3.cact": b"weights"}

    class FakeHF:
        @staticmethod
        def list_repo_files(repo, repo_type=None, revision=None):
            return [k for k in files if k.startswith("linux-x86_64/")]

        @staticmethod
        def hf_hub_download(repo_id, filename, repo_type=None, revision=None):
            p = tmp_path / "cache" / Path(filename).name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(files[filename])
            return str(p)

    monkeypatch.setitem(sys.modules, "huggingface_hub", FakeHF)
    dest = tmp_path / "out"
    rc = mod.main(["--platform", "linux-x86_64", "--dest", str(dest), "--with-weights"])
    assert rc == 0
    assert (dest / "needle").exists() and (dest / "needle3.cact").read_bytes() == b"weights"
