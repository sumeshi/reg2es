"""Unreadable startup values recover through actual REGF parsing."""

from pathlib import Path
import logging
import runpy

import orjson
import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from reg2es.plugins.run import Plugin

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)["make_hive"]
PATHS = {
    "NTUSER.DAT": r"Software\Microsoft\Windows\CurrentVersion",
    "SOFTWARE": r"Microsoft\Windows\CurrentVersion",
}


def _string(name, value):
    return name, 1, (value + "\0").encode("utf-16le")


def _write_hive(tmp_path, hive, scenario="normal"):
    values = [_string("a", "first.exe")]
    if scenario != "missing":
        # Native decoding fails only when b is read, after values enumerate.
        values.append(
            ("b", 7, b"a\0b\0c")
            if scenario == "unreadable"
            else _string("b", "middle.exe")
        )
    values.append(_string("c", "last.exe"))
    children = [
        ("Run", [], values),
        ("RunOnce", [], [_string("d", "later.exe")]),
    ]
    if scenario == "missing-key":
        children = children[1:]
    for name in reversed(PATHS[hive].split("\\")):
        children = [(name, children, [])]
    source = tmp_path / hive
    source.write_bytes(MAKE_HIVE(tree=children))
    if scenario == "unreadable-values":
        key = Registry.Registry(str(source)).open(PATHS[hive] + r"\Run")
        offset = key.values()[1]._vkrecord.offset()
        data = bytearray(source.read_bytes())
        assert data[offset : offset + 2] == b"vk"
        data[offset : offset + 2] = b"??"
        source.write_bytes(data)
    return source


def _documents(runner):
    return [document for chunk in runner.gen_records() for document in chunk]


@pytest.mark.parametrize("hive", PATHS)
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_run_value_recovers_later_values_and_keys(
    tmp_path, hive, chunk_size
):
    source = _write_hive(tmp_path, hive)
    baseline = reg2json(source, plugin_names=["run"], chunk_size=chunk_size)
    assert [doc["registry"]["value"] for doc in baseline] == ["a", "b", "c", "d"]
    source = _write_hive(tmp_path, hive, "unreadable")
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], chunk_size=chunk_size)

    documents = _documents(runner)

    assert documents == [doc for doc in baseline if doc["registry"]["value"] != "b"]
    assert runner.successful_records == 3
    assert runner.failed_records == 1
    diagnostic = runner.errors[0]
    assert diagnostic["plugin"] == "run"
    assert diagnostic["hive_path"] == str(source)
    assert diagnostic["key"] == "ROOT\\" + PATHS[hive] + r"\Run"
    assert diagnostic["value"] == "b"
    assert diagnostic["stage"] == "record"
    assert diagnostic["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["run"], chunk_size=chunk_size)
    assert caught.value.records == documents
    assert len(caught.value.diagnostics) == 1
    assert caught.value.diagnostics[0]["value"] == "b"
    assert source.read_bytes() == before


@pytest.mark.parametrize("hive", PATHS)
@pytest.mark.parametrize("scenario", ["missing", "missing-key"])
def test_absent_run_value_or_key_does_not_report_failure(tmp_path, hive, scenario):
    source = _write_hive(tmp_path, hive, scenario)
    runner = Reg2es(source, plugin_names=["run"])

    documents = _documents(runner)

    assert [doc["registry"]["value"] for doc in documents] == (
        ["a", "c", "d"] if scenario == "missing" else ["d"]
    )
    assert runner.failed_records == 0


@pytest.mark.parametrize("hive", PATHS)
def test_native_bad_run_value_strict_policy_reports_once(tmp_path, hive):
    source = _write_hive(tmp_path, hive, "unreadable")
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], chunk_size=1, error_policy="raise")
    records = runner.gen_records()
    try:
        assert next(records)[0]["registry"]["value"] == "a"
        with pytest.raises(UnicodeDecodeError):
            next(records)
        assert list(records) == []
        assert runner.successful_records == 1
        assert runner.failed_records == 1
        assert runner.errors[0]["key"] == "ROOT\\" + PATHS[hive] + r"\Run"
        assert runner.errors[0]["value"] == "b"
        assert runner.errors[0]["stage"] == "record"
    finally:
        records.close()
        assert source.read_bytes() == before


@pytest.mark.parametrize("hive", PATHS)
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_bad_run_key_honors_policy_before_later_key(tmp_path, hive, policy):
    source = _write_hive(tmp_path, hive, "unreadable-values")
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], error_policy=policy)

    if policy == "raise":
        with pytest.raises(Registry.RegistryParse.ParseException):
            _documents(runner)
        assert runner.successful_records == 0
    else:
        documents = _documents(runner)
        assert [doc["registry"]["value"] for doc in documents] == ["d"]
        assert runner.successful_records == 1
    assert runner.failed_records == 1
    assert runner.errors[0]["key"] == "ROOT\\" + PATHS[hive] + r"\Run"
    assert runner.errors[0]["value"] is None
    assert runner.errors[0]["stage"] == "values"
    assert source.read_bytes() == before


@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_run_key_open_error_reports_context_and_allows_next_key(
    tmp_path, monkeypatch, policy
):
    source = _write_hive(tmp_path, "NTUSER.DAT")
    registry = Registry.Registry(str(source))
    original_open = registry.open
    failing_path = PATHS["NTUSER.DAT"] + r"\Run"

    def open_key(path):
        if path == failing_path:
            raise ValueError("cannot decode key")
        return original_open(path)

    # Only the open boundary is injected; the following key uses the parser.
    monkeypatch.setattr(registry, "open", open_key)
    instance = Plugin(registry, logging.getLogger(__name__), "NTUSER.DAT", str(source))
    instance.error_policy = policy
    if policy == "raise":
        with pytest.raises(ValueError, match="cannot decode key"):
            list(instance.run())
    else:
        assert [result.value_name for result in instance.run()] == ["d"]
    assert len(instance.errors) == 1
    assert instance.errors[0]["key"] == failing_path
    assert instance.errors[0]["value"] is None
    assert instance.errors[0]["stage"] == "values"


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_native_cli_reports_partial_run_export_and_keeps_recovered_records(
    tmp_path, run_cli, output_format
):
    source = _write_hive(tmp_path, "NTUSER.DAT", "unreadable")
    original = source.read_bytes()
    output = tmp_path / ("records." + output_format)

    result = run_cli(
        "reg2json",
        [
            str(source),
            "--plugin",
            "run",
            "--format",
            output_format,
            "--quiet",
            "--output-file",
            str(output),
        ],
    )

    assert result.returncode == 1
    documents = (
        orjson.loads(output.read_bytes())
        if output_format == "json"
        else [orjson.loads(line) for line in output.read_bytes().splitlines()]
    )
    assert [record["registry"]["value"] for record in documents] == ["a", "c", "d"]
    assert "Partial extraction: 3 records written" in result.stderr
    assert "1 extraction failures" in result.stderr
    assert source.read_bytes() == original
