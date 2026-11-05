"""Events store hygiene: rotation, compaction, stats."""
import json

from plasma import store


def _write(path, n, dup_every=0):
    lines = []
    for i in range(n):
        lines.append(json.dumps({"ts": f"2026-11-05T10:{i % 60:02d}:{i:02d}Z",
                                 "kind": "process", "seq": i}))
        if dup_every and i % dup_every == 0:
            lines.append(lines[-1])
    path.write_text("\n".join(lines) + "\n")
    return lines


def test_rotate_under_limit_is_noop(tmp_path):
    f = tmp_path / "events.jsonl"
    _write(f, 10)
    result = store.rotate(f, max_mb=10, keep=3)
    assert result["rotated"] is False
    assert f.exists() and f.with_name(f.name + ".1").exists() is False


def test_rotate_over_limit_shifts_elders_and_respects_keep(tmp_path):
    f = tmp_path / "events.jsonl"
    _write(f, 50)
    # pretend elders already exist
    f.with_name(f.name + ".1").write_text("old1\n")
    f.with_name(f.name + ".2").write_text("old2\n")
    result = store.rotate(f, max_mb=0.00001, keep=2)
    assert result["rotated"] is True
    assert f.exists() and f.stat().st_size == 0, "fresh live file"
    assert f.with_name(f.name + ".1").read_text().startswith('{"ts"')
    assert f.with_name(f.name + ".2").read_text() == "old1\n"
    # .3 would exceed keep=2 → the previous .2 (old2) was removed
    assert not f.with_name(f.name + ".3").exists()


def test_rotate_missing_store_is_data(tmp_path):
    result = store.rotate(tmp_path / "nope.jsonl")
    assert result["rotated"] is False


def test_compact_drops_duplicates_order_insensitive(tmp_path):
    f = tmp_path / "events.jsonl"
    rows = [
        '{"ts": "2026-11-05T10:00:00Z", "kind": "process", "seq": 1}',
        '{"kind": "process", "ts": "2026-11-05T10:00:00Z", "seq": 1}',  # same row, key order flipped
        '{"ts": "2026-11-05T10:01:00Z", "kind": "process", "seq": 2}',
        '{"ts": "2026-11-05T10:01:00Z", "kind": "process", "seq": 2}',  # exact dup
    ]
    f.write_text("\n".join(rows) + "\n")
    result = store.compact(f)
    assert result["dropped_duplicates"] == 2
    assert result["kept"] == 2
    assert "after" in result["size_bytes"] and result["size_bytes"]["after"] < result["size_bytes"]["before"]
    # original replaced atomically
    assert not f.with_suffix(".jsonl.compact").exists()
    assert len(f.read_text().strip().splitlines()) == 2


def test_compact_preserves_torn_lines(tmp_path):
    f = tmp_path / "events.jsonl"
    f.write_text('{"a": 1}\n{"torn json...\nbanner line\n{"a": 1}\n')
    result = store.compact(f)
    assert result["dropped_duplicates"] == 1
    assert result["torn_or_noise_preserved"] == 2
    assert '{"torn json...' in f.read_text()
    assert "banner line" in f.read_text()


def test_compact_to_explicit_out_keeps_original(tmp_path):
    src = tmp_path / "events.jsonl"
    src.write_text('{"a": 1}\n{"a": 1}\n')
    out = tmp_path / "compact.jsonl"
    result = store.compact(src, out_path=out)
    assert result["written"] == str(out)
    assert src.read_text().count('{"a": 1}') == 2
    assert len(out.read_text().strip().splitlines()) == 1


def test_stats_counts_kinds_and_span(tmp_path):
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join([
        '{"ts": "2026-11-05T09:00:00Z", "kind": "process"}',
        '{"ts": "2026-11-05T10:00:00Z", "kind": "auth"}',
        '{"ts": "2026-11-05T10:30:00Z", "kind": "auth"}',
        "noise",
    ]) + "\n")
    s = store.stats(f)
    assert s["rows"] == 3
    assert s["kinds"] == {"process": 1, "auth": 2}
    assert s["first_ts"] == "2026-11-05T09:00:00Z"
    assert s["last_ts"] == "2026-11-05T10:30:00Z"
