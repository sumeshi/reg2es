"""Native VK name failures do not discard readable search history."""

from pathlib import Path
import runpy
import struct

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)["make_hive"]
KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"


def write_source(tmp_path, mru_name="MRUListEx"):
    values = [
        (str(index), 3, (term + "\0").encode("utf-16le"))
        for index, term in enumerate(("first", "middle", "last"))
    ]
    if mru_name is not None:
        values.append((mru_name, 3, struct.pack("<4I", 2, 0, 1, 0xFFFFFFFF)))
    children = []
    for name in reversed(KEY_PATH.split("\\")):
        children = [(name, children, [] if children else values)]
    source = tmp_path / "NTUSER.DAT"
    source.write_bytes(MAKE_HIVE(tree=children))
    return source


def damage_value_name(source, index):
    native = Registry.Registry(str(source))
    value = native.open(KEY_PATH).values()[index]
    offset = value._vkrecord.offset()
    data = bytearray(source.read_bytes())
    assert data[offset : offset + 2] == b"vk"
    # Keep the VK/data cells valid, but replace the name with a lone UTF-16
    # high surrogate and clear the compressed-ASCII-name flag.
    struct.pack_into("<H", data, offset + 2, 2)
    struct.pack_into("<H", data, offset + 16, 0)
    data[offset + 20 : offset + 22] = b"\x00\xd8"
    source.write_bytes(data)
    values = Registry.Registry(str(source)).open(KEY_PATH).values()
    assert len(values) == 4
    with pytest.raises(UnicodeDecodeError):
        values[index].name()


def documents(runner):
    return [document for chunk in runner.gen_records() for document in chunk]


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_value_name_keeps_other_searches_and_mru_order(tmp_path, chunk_size):
    source = write_source(tmp_path)
    baseline = reg2json(source, plugin_names=["wordwheelquery"])
    damage_value_name(source, 1)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=["wordwheelquery"], chunk_size=chunk_size)

    recovered = documents(runner)

    assert recovered == [baseline[0], baseline[2]]
    assert runner.successful_records == 2
    assert runner.failed_records == 1
    diagnostic = runner.errors[0]
    assert diagnostic["plugin"] == "wordwheelquery"
    assert diagnostic["key"] == "ROOT\\" + KEY_PATH
    assert diagnostic["value"] is None
    assert diagnostic["stage"] == "name"
    assert diagnostic["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["wordwheelquery"], chunk_size=chunk_size)
    assert caught.value.records == recovered
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_value_name_strict_is_recorded_once(tmp_path, chunk_size):
    source = write_source(tmp_path)
    damage_value_name(source, 1)
    original = source.read_bytes()
    runner = Reg2es(
        source,
        plugin_names=["wordwheelquery"],
        chunk_size=chunk_size,
        error_policy="raise",
    )

    with pytest.raises(UnicodeDecodeError):
        documents(runner)

    assert runner.successful_records == 0
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_unreadable_mru_name_keeps_searches_without_order(tmp_path, chunk_size):
    source = write_source(tmp_path)
    damage_value_name(source, 3)
    runner = Reg2es(source, plugin_names=["wordwheelquery"], chunk_size=chunk_size)

    recovered = documents(runner)

    assert [doc["reg2es"]["custom"]["search_term"] for doc in recovered] == [
        "first",
        "middle",
        "last",
    ]
    assert all(doc["reg2es"]["custom"]["mru_order"] == [] for doc in recovered)
    assert runner.successful_records == 3
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"


@pytest.mark.parametrize("mru_name", [None, "mRuLiStEx"])
def test_native_missing_or_mixed_case_mru_preserves_searches(tmp_path, mru_name):
    source = write_source(tmp_path, mru_name)
    runner = Reg2es(source, plugin_names=["wordwheelquery"])

    recovered = documents(runner)

    assert [doc["registry"]["value"] for doc in recovered] == ["0", "1", "2"]
    expected_order = [] if mru_name is None else ["2", "0", "1"]
    assert all(
        doc["reg2es"]["custom"]["mru_order"] == expected_order for doc in recovered
    )
    assert runner.failed_records == 0
