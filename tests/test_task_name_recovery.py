"""Native TaskCache name failures stay local to the unreadable entry."""

from pathlib import Path
import runpy
import struct

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from tests.test_complex_plugin_recovery import action, nested, string

ARTIFACT = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)
VERSION = r"Microsoft\Windows NT\CurrentVersion"
CACHE = VERSION + r"\Schedule\TaskCache"


def make_source(tmp_path, *, unrelated_position=None, categories=True, optional=True):
    tasks = []
    for name in "abc":
        values = [string("Path", "\\" + name)]
        if optional:
            dynamic = bytearray(36)
            for offset in (4, 12, 28):
                struct.pack_into("<Q", dynamic, offset, ARTIFACT["FILETIME"])
            values += [
                ("Actions", 3, action(name)),
                ("DynamicInfo", 3, bytes(dynamic)),
                string("Source", "source-" + name),
                string("Author", "author-" + name),
                string("Description", "description-" + name),
            ]
        if name == "b" and unrelated_position is not None:
            values.insert(unrelated_position, string("Unrelated", "unneeded"))
        tasks.append((name, [], values))
    children = [("Tasks", tasks, [])]
    if categories:
        children.insert(0, ("Boot", [(name, [], []) for name in "abc"], []))
    tree = nested(
        VERSION,
        [("Schedule", [("TaskCache", children, [])], [])],
        [string("CurrentBuild", "19045")],
    )
    source = tmp_path / "SOFTWARE"
    source.write_bytes(ARTIFACT["make_hive"](tree=tree))
    return source


def corrupt_name(source, *, key=None, value=None):
    native = Registry.Registry(str(source))
    raw = bytearray(source.read_bytes())
    record = native.open(key)
    if value is not None:
        record = record.value(value)
        offset = record._vkrecord.offset()
        struct.pack_into("<H", raw, offset + 2, 2)
        struct.pack_into("<H", raw, offset + 16, 0)
        raw[offset + 20 : offset + 22] = b"\x00\xd8"
    else:
        offset = record._nkrecord.offset()
        flags = struct.unpack_from("<H", raw, offset + 2)[0]
        struct.pack_into("<H", raw, offset + 2, flags & ~0x20)
        struct.pack_into("<H", raw, offset + 0x48, 2)
        raw[offset + 0x4C : offset + 0x4E] = b"\x00\xd8"
    source.write_bytes(raw)


def extract(source, chunk_size=500, policy="continue"):
    runner = Reg2es(
        source, plugin_names=["tasks"], chunk_size=chunk_size, error_policy=policy
    )
    documents = [doc for chunk in runner.gen_records() for doc in chunk]
    return documents, runner


def assert_partial(source, documents, chunk_size):
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["tasks"], chunk_size=chunk_size)
    assert caught.value.records == documents
    assert len(caught.value.diagnostics) == 1


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_unreadable_category_keeps_all_readable_tasks(tmp_path, chunk_size):
    source = make_source(tmp_path)
    baseline = reg2json(source, plugin_names=["tasks"])
    corrupt_name(source, key=CACHE + r"\Boot")
    original = source.read_bytes()
    native_children = Registry.Registry(str(source)).open(CACHE).subkeys()
    with pytest.raises(UnicodeDecodeError):
        native_children[0].name()
    assert native_children[1].name() == "Tasks"

    documents, runner = extract(source, chunk_size)

    expected = baseline
    for doc in expected:
        doc["reg2es"]["custom"]["RunType"] = "N/A"
    assert documents == expected
    assert runner.successful_records == 3 and runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    assert_partial(source, documents, chunk_size)
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_unreadable_guid_keeps_later_classification_and_tasks(tmp_path, chunk_size):
    source = make_source(tmp_path)
    baseline = reg2json(source, plugin_names=["tasks"])
    corrupt_name(source, key=CACHE + r"\Boot\b")
    original = source.read_bytes()
    documents, runner = extract(source, chunk_size)

    baseline[1]["reg2es"]["custom"]["RunType"] = "N/A"
    assert documents == baseline
    assert [doc["reg2es"]["custom"]["RunType"] for doc in documents] == [
        "Boot",
        "N/A",
        "Boot",
    ]
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    assert_partial(source, documents, chunk_size)
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize("position", [0, 2, 6])
def test_unrelated_bad_value_name_does_not_hide_task_fields(
    tmp_path, chunk_size, position
):
    source = make_source(tmp_path, unrelated_position=position)
    baseline = reg2json(source, plugin_names=["tasks"])
    corrupt_name(source, key=CACHE + r"\Tasks\b", value="Unrelated")
    original = source.read_bytes()
    native_values = Registry.Registry(str(source)).open(CACHE + r"\Tasks\b").values()
    with pytest.raises(UnicodeDecodeError):
        native_values[position].name()
    documents, runner = extract(source, chunk_size)

    assert documents == baseline
    assert runner.successful_records == 3 and runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    middle = documents[1]["reg2es"]["custom"]
    assert middle["Path"].endswith(r"\b")
    assert middle["Actions"]["cmd"] == "b"
    assert middle["DynamicInfo"]["last_start"] == ARTIFACT["FILETIME"]
    assert middle["Source"] == "source-b"
    assert middle["Author"] == "author-b"
    assert middle["Description"] == "description-b"
    assert_partial(source, documents, chunk_size)
    assert source.read_bytes() == original


@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize("location", ["category", "guid", "value"])
def test_strict_name_failure_is_recorded_once(tmp_path, chunk_size, location):
    source = make_source(tmp_path, unrelated_position=0)
    if location == "category":
        corrupt_name(source, key=CACHE + r"\Boot")
    elif location == "guid":
        corrupt_name(source, key=CACHE + r"\Boot\b")
    else:
        corrupt_name(source, key=CACHE + r"\Tasks\b", value="Unrelated")
    original = source.read_bytes()
    runner = Reg2es(
        source, plugin_names=["tasks"], error_policy="raise", chunk_size=chunk_size
    )

    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())
    assert runner.failed_records == 1 and len(runner.errors) == 1
    assert runner.errors[0]["stage"] == "name"
    assert source.read_bytes() == original


def test_optional_keys_and_values_remain_optional(tmp_path):
    source = make_source(tmp_path, categories=False, optional=False)
    documents, runner = extract(source)

    assert len(documents) == 3 and runner.failed_records == 0
    for doc in documents:
        custom = doc["reg2es"]["custom"]
        assert custom["RunType"] == "N/A"
        assert custom["Actions"] == {"runas": None, "cmd": None}
        assert custom["Source"] is custom["Author"] is custom["Description"] is None
        assert custom["DynamicInfo"]["raw"] is None


def test_required_path_keeps_case_insensitive_lookup(tmp_path):
    source = make_source(tmp_path)
    native = Registry.Registry(str(source))
    values = native.open(CACHE + r"\Tasks\b")
    raw = bytearray(source.read_bytes())
    for old_name in ("Path", "Source"):
        offset = values.value(old_name)._vkrecord.offset()
        raw[offset + 20 : offset + 20 + len(old_name)] = old_name.lower().encode(
            "ascii"
        )
    source.write_bytes(raw)

    documents, runner = extract(source)

    assert len(documents) == 3 and runner.failed_records == 0
    assert documents[1]["reg2es"]["custom"]["Path"].endswith(r"\b")
    # The existing optional-value presence check is case-sensitive.
    assert documents[1]["reg2es"]["custom"]["Source"] is None
