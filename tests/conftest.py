import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTANCE = ROOT / "instance"
SAMPLES = ROOT / "samples" / "plasma_events.jsonl"

if str(INSTANCE) not in sys.path:
    sys.path.insert(0, str(INSTANCE))


@pytest.fixture(scope="session")
def instance_dir() -> Path:
    return INSTANCE


@pytest.fixture(scope="session")
def samples() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def bridge():
    import bridge as bridge_module
    os.environ.setdefault("PLASMA_EVENTS", str(SAMPLES))
    return bridge_module


@pytest.fixture(scope="session")
def rows(samples):
    return [json.loads(line) for line in samples.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_ps_bridge(tool, args=None, events=None):
    cmd = ["pwsh", "-NoProfile", "-File", str(INSTANCE / "bridge.ps1"),
           "-Tool", tool, "-ArgsJson", json.dumps(args or {})]
    if events:
        cmd += ["-EventsPath", str(events)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def engine_paths():
    engine = os.environ.get("PLASMA_ENGINE")
    model = os.environ.get("PLASMA_MODEL")
    if engine and model and Path(engine).exists() and Path(model).exists():
        return Path(engine), Path(model)
    return None, None
