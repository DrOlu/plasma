"""Plan-gated responder actions: preview, apply, undo, permissions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from plasma import killswitch, plugin_actions, plugin_api, plugins

NAME = "act-responder"
ACTION = "act-responder.touch"


def _install(tmp_path, enabled=True):
    source = tmp_path / "src"
    plugins.scaffold(source, NAME, "responder")
    root = tmp_path / "root"
    plugins.install(root, source / NAME, allow_unsigned=True, enable=enabled)
    return root, source / NAME


def _args(root):
    return {"path": str(root / "plugin-samples" / "touch.txt")}


def test_preview_creates_a_plan_without_touching_the_host(tmp_path):
    root, _ = _install(tmp_path)
    result = plugin_actions.preview(root, ACTION, _args(root))
    assert result["ok"] is True and result["dry_run"] is True
    assert result["plan_id"]
    assert str(Path(result["plan"])).endswith(result["plan_id"] + ".json")
    assert not (root / "plugin-samples" / "touch.txt").exists()
    plan = json.loads(Path(result["plan"]).read_text())
    assert plan["apply"] and plan["rollback"]


def test_apply_requires_plan_and_reason(tmp_path):
    root, _ = _install(tmp_path)
    args = _args(root)
    preview = plugin_actions.preview(root, ACTION, args)
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.apply(root, ACTION, args, "", "reason")
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.apply(root, ACTION, args, "deadbeef", "reason")
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.apply(root, ACTION, args, preview["plan_id"], "")
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.apply(root, ACTION, {"path": str(root / "elsewhere")},
                             preview["plan_id"], "reason")


def test_apply_verifies_and_undo_rolls_back(tmp_path):
    root, _ = _install(tmp_path)
    args = _args(root)
    preview = plugin_actions.preview(root, ACTION, args)
    applied = plugin_actions.apply(root, ACTION, args, preview["plan_id"],
                                   "unit test")
    target = Path(args["path"])
    assert applied["ok"] is True
    assert target.exists()
    assert applied["verify"]["ok"] is True
    undone = plugin_actions.undo(root, applied["journal_id"], "cleanup")
    assert undone["ok"] is True
    assert not target.exists()
    journal = (root / plugin_actions.JOURNAL).read_text().splitlines()
    assert len(journal) == 2
    assert json.loads(journal[0])["kind"] == "apply"
    assert json.loads(journal[1])["kind"] == "undo"


def test_disabled_plugin_cannot_apply(tmp_path):
    root, _ = _install(tmp_path, enabled=False)
    args = _args(root)
    preview = plugin_actions.preview(root, ACTION, args)
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.apply(root, ACTION, args, preview["plan_id"], "reason")


def test_kill_switch_blocks_apply_and_undo(tmp_path):
    root, _ = _install(tmp_path)
    args = _args(root)
    preview = plugin_actions.preview(root, ACTION, args)
    applied = plugin_actions.apply(root, ACTION, args, preview["plan_id"],
                                   "unit test")
    killswitch.set_global(root, True, "test")
    try:
        with pytest.raises(plugin_api.PluginError):
            plugin_actions.apply(root, ACTION, args, preview["plan_id"],
                                 "reason")
        with pytest.raises(plugin_api.PluginError):
            plugin_actions.undo(root, applied["journal_id"], "reason")
    finally:
        killswitch.set_global(root, False, "test done")


def test_unknown_arguments_are_refused(tmp_path):
    root, _ = _install(tmp_path)
    with pytest.raises(plugin_api.PluginError):
        plugin_actions.preview(root, ACTION, {"path": "x", "extra": "y"})


def test_actions_are_listed_with_schema(tmp_path):
    root, _ = _install(tmp_path)
    listing = plugin_actions.list_actions(root)
    assert listing["ok"] is True
    assert listing["actions"][0]["name"] == ACTION
    assert "path" in listing["actions"][0]["args_schema"]["properties"]


def test_cli_act_accepts_args_file(tmp_path, capsys):
    import json as _json
    from plasma import cli

    root, _ = _install(tmp_path)
    args_file = tmp_path / "args.json"
    args_file.write_text(_json.dumps(_args(root)))
    code = cli.main(["plugin", "act", ACTION, "--args-file", str(args_file),
                     "--root", str(root)])
    assert code == 0
    preview = _json.loads(capsys.readouterr().out)
    assert preview["ok"] is True and preview["plan_id"]
