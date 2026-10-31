"""UserAssist recovery through native REGF inputs and the real parser."""

import codecs
from pathlib import Path
import runpy
import struct

import orjson
import pytest
from Registry import Registry, RegistryParse

from reg2es.models.Reg2es import Reg2es

FIXTURE_MODULE = Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py"
USERASSIST_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
OTHER_GUID = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
COUNT_PATH = "ROOT\\" + USERASSIST_PATH + "\\" + GUID + r"\Count"
FILETIME = 133485408001234560


def _value(name, *, invalid=False):
    if invalid:
        kind, raw = 4, struct.pack("<I", 5)
    else:
        kind, raw = 3, bytearray(72)
        struct.pack_into("<I", raw, 4, 3)
        struct.pack_into("<Q", raw, 60, FILETIME)
        raw = bytes(raw)
    return codecs.encode(name, "rot13"), kind, raw


def _write_hive(tmp_path, subkeys):
    tree = subkeys
    for name in reversed(USERASSIST_PATH.split("\\")):
        tree = [(name, tree, [])]
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(runpy.run_path(str(FIXTURE_MODULE))["make_hive"](tree=tree))
    return source


def _values_hive(tmp_path, *, invalid=False):
    values = [
        _value("first.exe"),
        _value("middle.exe", invalid=invalid),
        _value("last.exe"),
    ]
    return _write_hive(tmp_path, [(GUID, [("Count", [], values)], [])])


def _count_failure_hive(tmp_path, kind):
    first_children = [] if kind == "missing" else [("Count", [], [_value("bad.exe")])]
    source = _write_hive(
        tmp_path,
        [
            (GUID, first_children, []),
            (OTHER_GUID, [("Count", [], [_value("last.exe")])], []),
        ],
    )
    if kind == "unreadable":
        # Corrupt one VK signature so the native parser cannot enumerate the
        # first Count's values. The later GUID and its values remain readable.
        count = Registry.Registry(str(source)).open(
            USERASSIST_PATH + "\\" + GUID + r"\Count"
        )
        offset = count.values()[0]._vkrecord.offset()
        raw = bytearray(source.read_bytes())
        assert raw[offset : offset + 2] == b"vk"
        raw[offset : offset + 2] = b"??"
        source.write_bytes(raw)
    return source


def _read(source, *, chunk_size=500):
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=["userassist"], chunk_size=chunk_size)
    try:
        documents = [doc for chunk in runner.gen_records() for doc in chunk]
    finally:
        runner.close()
        assert source.read_bytes() == original
    return documents, runner


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_value_recovers_neighbors_without_changing_documents(
    tmp_path, chunk_size
):
    source = _values_hive(tmp_path)
    baseline, baseline_runner = _read(source, chunk_size=chunk_size)
    assert len(baseline) == 3 and baseline_runner.failed_records == 0
    source = _values_hive(tmp_path, invalid=True)

    documents, runner = _read(source, chunk_size=chunk_size)

    assert documents == [baseline[0], baseline[2]]
    assert runner.successful_records == 2
    assert runner.failed_records == 1
    assert runner.errors == [
        {
            "plugin": "userassist",
            "hive": "NTUSER.DAT",
            "hive_path": str(source),
            "key": COUNT_PATH,
            "value": codecs.encode("middle.exe", "rot13"),
            "error": "TypeError: object of type 'int' has no len()",
            "stage": "record",
        }
    ]


def test_native_bad_value_strict_policy_reports_once_and_stops(tmp_path):
    source = _values_hive(tmp_path, invalid=True)
    original = source.read_bytes()
    runner = Reg2es(
        source, plugin_names=["userassist"], error_policy="raise", chunk_size=1
    )
    records = runner.gen_records()
    try:
        assert next(records)[0]["reg2es"]["custom"]["userassist"]["name"] == "first.exe"
        with pytest.raises(TypeError, match="has no len"):
            next(records)
        assert list(records) == []
        assert runner.successful_records == 1
        assert runner.failed_records == 1
        assert runner.errors[0]["key"] == COUNT_PATH
        assert runner.errors[0]["value"] == codecs.encode("middle.exe", "rot13")
        assert runner.errors[0]["stage"] == "record"
    finally:
        records.close()
        runner.close()
        assert source.read_bytes() == original


@pytest.mark.parametrize("kind", ["missing", "unreadable"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_count_failure_recovers_the_next_guid(tmp_path, kind, chunk_size):
    source = _count_failure_hive(tmp_path, kind)

    documents, runner = _read(source, chunk_size=chunk_size)

    assert [doc["reg2es"]["custom"]["userassist"]["name"] for doc in documents] == [
        "last.exe"
    ]
    assert runner.successful_records == 1
    assert runner.failed_records == 1
    assert runner.errors[0]["key"] == COUNT_PATH
    assert runner.errors[0]["value"] is None
    assert runner.errors[0]["stage"] == "values"


@pytest.mark.parametrize(
    "kind,error",
    [
        ("missing", Registry.RegistryKeyNotFoundException),
        ("unreadable", RegistryParse.ParseException),
    ],
)
def test_native_count_failure_strict_policy_stops_before_next_guid(
    tmp_path, kind, error
):
    source = _count_failure_hive(tmp_path, kind)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=["userassist"], error_policy="raise")
    try:
        with pytest.raises(error):
            list(runner.gen_records())
        assert runner.successful_records == 0
        assert runner.failed_records == 1
        assert runner.errors[0]["key"] == COUNT_PATH
        assert runner.errors[0]["stage"] == "values"
    finally:
        runner.close()
        assert source.read_bytes() == original


def test_native_cli_publishes_recovered_records_and_reports_partial_success(
    tmp_path, run_cli
):
    source = _values_hive(tmp_path, invalid=True)
    original = source.read_bytes()
    output = tmp_path / "recovered.jsonl"

    result = run_cli(
        "reg2json",
        [
            str(source),
            "--plugin",
            "userassist",
            "--format",
            "jsonl",
            "--quiet",
            "--output-file",
            str(output),
        ],
    )

    assert result.returncode == 1
    documents = [orjson.loads(line) for line in output.read_bytes().splitlines()]
    assert [doc["reg2es"]["custom"]["userassist"]["name"] for doc in documents] == [
        "first.exe",
        "last.exe",
    ]
    assert "Partial extraction: 2 records written" in result.stderr
    assert "1 extraction failures" in result.stderr
    assert source.read_bytes() == original
