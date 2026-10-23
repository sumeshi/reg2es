"""Recover readable registry keys while reporting regtime extraction failures."""

from pathlib import Path
from unittest.mock import Mock

import orjson
import pytest

from reg2es.models.Reg2es import Reg2es
from tests.regrippy.reg_mock import RegistryKeyMock, RegistryMock


def _tree():
    root = RegistryKeyMock("ROOT", None)
    bad = RegistryKeyMock("Bad", root)
    child = RegistryKeyMock("Child", bad)
    sibling = RegistryKeyMock("Sibling", root)
    root.add_child(bad)
    bad.add_child(child)
    root.add_child(sibling)
    return RegistryMock("SYSTEM", "system", root), bad, child, sibling


def _runner(monkeypatch, registry, *, policy="continue", chunk_size=1):
    monkeypatch.setattr(
        "reg2es.models.Reg2es._build_hive_dataset",
        lambda _paths, *_args: {"SYSTEM": [(Path("/case/SYSTEM"), registry)]},
    )
    return Reg2es(
        "/case/SYSTEM", plugin_names=["regtime"],
        error_policy=policy, chunk_size=chunk_size,
    )


@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize("failure", [
    ValueError("unreadable timestamp"),
    UnicodeDecodeError("utf-16-le", b"\x00", 0, 1, "truncated data"),
])
def test_bad_key_record_does_not_hide_readable_descendants(
    monkeypatch, chunk_size, failure,
):
    registry, bad, _child, _sibling = _tree()
    bad.timestamp = Mock(side_effect=failure)
    runner = _runner(monkeypatch, registry, chunk_size=chunk_size)

    documents = [document for chunk in runner.gen_records() for document in chunk]

    assert [doc["reg2es"]["source"]["key_path"] for doc in documents] == [
        "\\ROOT", "\\ROOT\\Bad\\Child", "\\ROOT\\Sibling",
    ]
    assert runner.successful_records == 3
    assert runner.failed_records == 1
    assert runner.errors == [{
        "plugin": "regtime", "hive": "SYSTEM", "hive_path": str(Path("/case/SYSTEM")),
        "key": "\\ROOT\\Bad", "value": None,
        "error": f"{type(failure).__name__}: {failure}",
        "stage": "metadata",
    }]


def test_bad_key_record_obeys_strict_policy_without_duplicate_errors(monkeypatch):
    registry, bad, child, _sibling = _tree()
    failure = ValueError("unreadable timestamp")
    bad.timestamp = Mock(side_effect=failure)
    child.timestamp = Mock(wraps=child.timestamp)
    runner = _runner(monkeypatch, registry, policy="raise")
    records = runner.gen_records()
    assert next(records)[0]["reg2es"]["source"]["key_path"] == "\\ROOT"

    with pytest.raises(ValueError) as raised:
        list(records)

    assert raised.value is failure
    assert runner.successful_records == 1
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "metadata"
    child.timestamp.assert_not_called()


@pytest.mark.parametrize("policy", ["continue", "raise"])
@pytest.mark.parametrize("lazy", [False, True])
def test_unreadable_subkeys_preserve_previous_results_and_siblings(
    monkeypatch, policy, lazy,
):
    registry, bad, child, _sibling = _tree()
    failure = ValueError("unreadable subkeys")
    if lazy:
        def subkeys():
            yield child
            raise failure

        bad.subkeys = subkeys
    else:
        bad.subkeys = Mock(side_effect=failure)
    runner = _runner(monkeypatch, registry, policy=policy)
    records = runner.gen_records()
    documents = [next(records)[0], next(records)[0]]
    if lazy:
        documents.append(next(records)[0])

    if policy == "raise":
        with pytest.raises(ValueError) as raised:
            list(records)
        assert raised.value is failure
    else:
        documents.extend(doc for chunk in records for doc in chunk)

    expected = ["\\ROOT", "\\ROOT\\Bad"]
    if lazy:
        expected.append("\\ROOT\\Bad\\Child")
    if policy == "continue":
        expected.append("\\ROOT\\Sibling")
    assert [doc["reg2es"]["source"]["key_path"] for doc in documents] == expected
    assert runner.successful_records == len(expected)
    assert runner.failed_records == 1
    assert runner.errors[0]["key"] == "\\ROOT\\Bad"
    assert runner.errors[0]["error"] == "ValueError: unreadable subkeys"
    assert runner.errors[0]["stage"] == "subkeys"


def test_unreadable_key_recovers_children_with_readable_full_paths(monkeypatch):
    registry, bad, child, _sibling = _tree()
    bad.path = Mock(side_effect=ValueError("unreadable path"))
    # This case requires independently readable child paths. A native parser
    # path that also decodes an unreadable ancestor name cannot meet that
    # requirement; the separate test below covers that limitation.
    child.path = Mock(return_value="\\ROOT\\Bad\\Child")
    runner = _runner(monkeypatch, registry)

    documents = [document for chunk in runner.gen_records() for document in chunk]

    assert len(documents) == 3
    assert runner.failed_records == 1
    assert runner.errors[0]["key"] == "<unreadable>"
    assert documents[1]["reg2es"]["source"]["key_path"] == "\\ROOT\\Bad\\Child"


def test_unreadable_ancestor_name_reports_descendant_path_failures(monkeypatch):
    registry, bad, child, _sibling = _tree()
    bad.name = Mock(side_effect=UnicodeDecodeError(
        "utf-16-le", b"\x00", 0, 1, "truncated data",
    ))
    bad.subkeys = Mock(wraps=bad.subkeys)
    child.subkeys = Mock(wraps=child.subkeys)
    runner = _runner(monkeypatch, registry)

    documents = [document for chunk in runner.gen_records() for document in chunk]

    assert [doc["reg2es"]["source"]["key_path"] for doc in documents] == [
        "\\ROOT", "\\ROOT\\Sibling",
    ]
    bad.subkeys.assert_called_once_with()
    child.subkeys.assert_called_once_with()
    assert runner.successful_records == 2
    assert runner.failed_records == 2
    assert [error["key"] for error in runner.errors] == [
        "<unreadable>", "<unreadable>",
    ]
    assert [error["stage"] for error in runner.errors] == ["metadata", "metadata"]


def test_same_key_and_error_text_distinguish_failed_operations(monkeypatch):
    registry, bad, _child, _sibling = _tree()
    bad.timestamp = Mock(side_effect=ValueError("unreadable"))
    bad.subkeys = Mock(side_effect=ValueError("unreadable"))
    runner = _runner(monkeypatch, registry)

    documents = [document for chunk in runner.gen_records() for document in chunk]

    assert len(documents) == 2
    assert runner.failed_records == 2
    assert [error["error"] for error in runner.errors] == ["ValueError: unreadable"] * 2
    assert [error["key"] for error in runner.errors] == ["\\ROOT\\Bad"] * 2
    assert [error["stage"] for error in runner.errors] == ["metadata", "subkeys"]


@pytest.mark.parametrize("quiet", [False, True])
def test_regtime_cli_finalizes_recovered_records_and_exits_nonzero(
    tmp_path, monkeypatch, capsys, quiet,
):
    from reg2es.views.Reg2jsonView import entry_point

    source = tmp_path / "SYSTEM"
    source.write_bytes(b"regf synthetic header")
    destination = tmp_path / "recovered.jsonl"
    registry, bad, _child, _sibling = _tree()
    bad.timestamp = Mock(side_effect=ValueError("unreadable timestamp"))
    monkeypatch.setattr(
        "reg2es.models.Reg2es._build_hive_dataset",
        lambda _paths, *_args: {"SYSTEM": [(source, registry)]},
    )
    arguments = [
        "reg2json", str(source), "-o", str(destination),
        "--format", "jsonl", "--plugin", "regtime",
    ]
    if quiet:
        arguments.append("--quiet")
    monkeypatch.setattr("sys.argv", arguments)

    with pytest.raises(SystemExit) as exited:
        entry_point()

    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert "3 records written; 0 input failures; 1 extraction failures" in captured.err
    assert "completed successfully" not in captured.out
    documents = [orjson.loads(line) for line in destination.read_bytes().splitlines()]
    assert len(documents) == 3
    assert documents[1]["reg2es"]["source"]["key_path"] == "\\ROOT\\Bad\\Child"
