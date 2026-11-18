"""The agent-facing help surface: completeness, examples and JSON catalog."""

import argparse
import json

import pytest

from plasma import cli
from plasma import help as helpmod


def _walk(parser, path=()):
    yield path, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from _walk(child, path + (name,))


def test_every_parser_node_has_a_help_entry():
    missing = []
    for path, _node in _walk(cli.build_parser()):
        if not path:
            continue
        if " ".join(path) not in helpmod.COMMANDS:
            missing.append(" ".join(path))
    assert missing == []


def test_every_help_entry_is_detailed():
    for command, spec in helpmod.COMMANDS.items():
        assert spec["summary"], command
        assert spec["description"], command
        assert spec["examples"], command
        assert spec["safety"], command
        assert spec["output"], command
        for title, example in spec["examples"]:
            assert title and example, command


def test_every_command_help_has_examples(capsys):
    for path, _node in _walk(cli.build_parser()):
        if not path:
            continue
        with pytest.raises(SystemExit) as exc:
            cli.main([*path, "--help"])
        assert exc.value.code == 0, path
        out = capsys.readouterr().out
        assert "EXAMPLES" in out, " ".join(path)
        assert "SAFETY" in out, " ".join(path)


def test_root_help_points_at_the_agent_paths(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "AGENT QUICK START" in out
    assert "plasma help --json" in out
    assert "0 success or clean" in out


def test_help_overview_has_groups_and_workflow(capsys):
    assert cli.main(["help"]) == 0
    out = capsys.readouterr().out
    assert "AGENT WORKFLOW" in out
    assert "RESPONSE AND PREVENTION" in out
    assert "plasma help --json" in out


def test_help_topic_matches_argparse_help(capsys):
    assert cli.main(["help", "control", "approvals", "approve"]) == 0
    text = capsys.readouterr().out
    assert "Record a human approval" in text
    assert "EXAMPLES" in text
    assert "control approvals approve 17" in text


def test_help_topic_json(capsys):
    assert cli.main(["help", "prevent", "asr", "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["command"] == "prevent asr"
    assert body["leaf"] is True
    assert body["arguments"]
    assert body["examples"]
    assert body["safety"].startswith("plan-gated")


def test_unknown_help_topic_is_a_structured_error(capsys):
    assert cli.main(["help", "not-a-command"]) == 1
    err = capsys.readouterr().err
    body = json.loads(err)
    assert body["ok"] is False
    assert "unknown command path" in body["error"]


def test_help_json_catalog_is_complete_and_parseable(capsys):
    assert cli.main(["help", "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["schema"] == "plasma.help/1"
    assert body["product"] == "Plasma"
    assert body["commands"]
    paths = {row["command"] for row in body["commands"]}
    assert "help" in paths
    assert "actuate apply" in paths
    assert "control approvals approve" in paths
    assert "update auto" in paths
    for row in body["commands"]:
        assert row["usage"].startswith("usage: plasma"), row["command"]
        assert "arguments" in row
        assert "subcommands" in row
        if not row["hidden"]:
            assert row["examples"], row["command"]
            assert row["summary"], row["command"]


def test_catalog_documents_the_dry_run_to_plan_workflow():
    body = helpmod.catalog(cli.build_parser())
    rows = {row["command"]: row for row in body["commands"]}
    commands = [e["command"] for e in rows["actuate apply"]["examples"]]
    assert any("--apply --plan" in c for c in commands)
    undos = [e["command"] for e in rows["actuate undo"]["examples"]]
    assert any("--apply --plan" in c for c in undos)


def test_help_command_is_in_the_serve_tree():
    # /v1/commands is built from the same parser and hides names starting "_".
    from plasma.serve import _command_tree

    rows = _command_tree(cli.build_parser())
    paths = {tuple(row["path"]) for row in rows}
    assert ("help",) in paths
    assert ("_bridge",) not in paths
