"""MRU references and unreadable values recover through real REGF parsing."""

from pathlib import Path
import importlib
import logging
import runpy

import orjson
import pytest
from Registry import Registry

from reg2es.models.Reg2es import Reg2es

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)["make_hive"]
EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
PATHS = {
    "runmru": EXPLORER + r"\RunMRU",
    "mndmru": EXPLORER + r"\Map Network Drive MRU",
    "filedialogmru": EXPLORER + r"\ComDlg32\OpenSaveMRU",
}
LATER_PATH = EXPLORER + r"\ComDlg32\LastVisitedMRU"


def _string(name, value):
    return name, 1, (value + "\0").encode("utf-16le")


def _write_hive(tmp_path, plugin, scenario):
    values = [_string("MRUList", "abc"), _string("a", "first")]
    if scenario != "missing":
        # An odd-length REG_MULTI_SZ is enumerable but fails native decoding.
        values.append(
            ("b", 7, b"a\0b\0c") if scenario == "unreadable" else _string("b", "middle")
        )
    values.append(_string("c", "last"))
    if scenario == "missing-order":
        values = values[1:]
    elif scenario == "unreadable-order":
        values[0] = ("MRUList", 7, b"a\0b\0c")

    branches = {}

    def add(path, entries):
        children = branches
        for name in path.split("\\"):
            node = children.setdefault(name, {"children": {}, "values": []})
            children = node["children"]
        node["values"] = entries

    def tree(children):
        return [
            (name, tree(node["children"]), node["values"])
            for name, node in children.items()
        ]

    add(PATHS[plugin], values)
    if plugin == "filedialogmru":
        add(LATER_PATH, [_string("MRUList", "d"), _string("d", "later key")])
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(MAKE_HIVE(tree=tree(branches)))
    return source


def _read(source, plugin, *, chunk_size=500, policy="continue"):
    before = source.read_bytes()
    runner = Reg2es(
        source, plugin_names=[plugin], chunk_size=chunk_size, error_policy=policy
    )
    try:
        documents = [document for chunk in runner.gen_records() for document in chunk]
    finally:
        runner.close()
        assert source.read_bytes() == before
    return documents, runner


@pytest.mark.parametrize("plugin", PATHS)
@pytest.mark.parametrize("scenario", ["missing", "unreadable"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_mru_entry_recovers_later_values_and_keys(
    tmp_path, plugin, scenario, chunk_size
):
    source = _write_hive(tmp_path, plugin, "normal")
    baseline, normal_runner = _read(source, plugin, chunk_size=chunk_size)
    assert normal_runner.failed_records == 0
    assert [record["registry"]["value"] for record in baseline] == (
        ["a", "b", "c", "d"] if plugin == "filedialogmru" else ["a", "b", "c"]
    )
    source = _write_hive(tmp_path, plugin, scenario)

    documents, runner = _read(source, plugin, chunk_size=chunk_size)

    assert documents == [
        record for record in baseline if record["registry"]["value"] != "b"
    ]
    assert runner.successful_records == len(documents)
    assert runner.failed_records == 1
    diagnostic = runner.errors[0]
    assert diagnostic["plugin"] == plugin
    assert diagnostic["hive_path"] == str(source)
    assert diagnostic["key"] == "ROOT\\" + PATHS[plugin]
    assert diagnostic["value"] == "b"
    assert diagnostic["stage"] == "record"
    assert diagnostic["error"].startswith(
        "KeyError:" if scenario == "missing" else "UnicodeDecodeError:"
    )


@pytest.mark.parametrize("plugin", PATHS)
@pytest.mark.parametrize(
    "scenario,error", [("missing", KeyError), ("unreadable", UnicodeDecodeError)]
)
def test_native_bad_mru_entry_strict_policy_reports_once(
    tmp_path, plugin, scenario, error
):
    source = _write_hive(tmp_path, plugin, scenario)
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], chunk_size=1, error_policy="raise")
    records = runner.gen_records()
    try:
        assert next(records)[0]["registry"]["value"] == "a"
        with pytest.raises(error):
            next(records)
        assert list(records) == []
        assert runner.successful_records == 1
        assert runner.failed_records == 1
        assert runner.errors[0]["key"] == "ROOT\\" + PATHS[plugin]
        assert runner.errors[0]["value"] == "b"
        assert runner.errors[0]["stage"] == "record"
    finally:
        records.close()
        runner.close()
        assert source.read_bytes() == before


@pytest.mark.parametrize(
    "scenario", ["missing-order", "unreadable-order", "unreadable-values"]
)
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_bad_mru_key_honors_policy_before_later_key(tmp_path, scenario, policy):
    source = _write_hive(tmp_path, "filedialogmru", scenario)
    if scenario == "unreadable-values":
        # Damage an enumerated VK signature in the first key only. Later
        # LastVisitedMRU remains usable even though OpenSaveMRU cannot enumerate.
        key = Registry.Registry(str(source)).open(PATHS["filedialogmru"])
        offset = key.values()[1]._vkrecord.offset()
        raw = bytearray(source.read_bytes())
        assert raw[offset : offset + 2] == b"vk"
        raw[offset : offset + 2] = b"??"
        source.write_bytes(raw)
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["filedialogmru"], error_policy=policy)
    try:
        if policy == "raise":
            with pytest.raises(Exception):
                list(runner.gen_records())
            assert runner.successful_records == 0
        else:
            documents = [doc for chunk in runner.gen_records() for doc in chunk]
            assert [doc["registry"]["value"] for doc in documents] == ["d"]
            assert runner.successful_records == 1
        assert runner.failed_records == 1
        assert runner.errors[0]["key"] == "ROOT\\" + PATHS["filedialogmru"]
        assert runner.errors[0]["value"] is None
        assert runner.errors[0]["stage"] == "values"
    finally:
        runner.close()
        assert source.read_bytes() == before


def test_native_cli_reports_partial_mru_export_and_keeps_recovered_records(
    tmp_path, run_cli
):
    source = _write_hive(tmp_path, "runmru", "missing")
    original = source.read_bytes()
    output = tmp_path / "records.jsonl"

    result = run_cli(
        "reg2json",
        [
            str(source),
            "--plugin",
            "runmru",
            "--format",
            "jsonl",
            "--quiet",
            "--output-file",
            str(output),
        ],
    )

    assert result.returncode == 1
    documents = [orjson.loads(line) for line in output.read_bytes().splitlines()]
    assert [record["registry"]["value"] for record in documents] == ["a", "c"]
    assert "Partial extraction: 2 records written" in result.stderr
    assert "1 extraction failures" in result.stderr
    assert source.read_bytes() == original


@pytest.mark.parametrize("plugin", PATHS)
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_key_open_failure_reports_context_and_allows_later_keys(
    tmp_path, monkeypatch, plugin, policy
):
    source = _write_hive(tmp_path, plugin, "normal")
    registry = Registry.Registry(str(source))
    original_open = registry.open

    def open_key(path):
        if path == PATHS[plugin]:
            raise ValueError("cannot decode key")
        return original_open(path)

    # Isolate the key-opening boundary; later keys still use the real parser.
    monkeypatch.setattr(registry, "open", open_key)
    plugin_class = importlib.import_module("reg2es.plugins." + plugin).Plugin
    instance = plugin_class(
        registry, logging.getLogger(__name__), "NTUSER.DAT", str(source)
    )
    instance.error_policy = policy
    if policy == "raise":
        with pytest.raises(ValueError, match="cannot decode key"):
            list(instance.run())
    else:
        results = list(instance.run())
        assert [result.value_name for result in results] == (
            ["d"] if plugin == "filedialogmru" else []
        )
    assert len(instance.errors) == 1
    assert instance.errors[0]["key"] == PATHS[plugin]
    assert instance.errors[0]["value"] is None
    assert instance.errors[0]["stage"] == "values"
