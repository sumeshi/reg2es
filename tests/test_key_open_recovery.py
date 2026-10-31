"""Fixed-path opens recover native sibling-name errors without losing evidence."""

import logging

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from reg2es.plugins.base import BasePlugin
from tests.test_other_plugin_recovery import sz, write_hive
from tests.test_task_name_recovery import corrupt_name

PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
)
PARENT = r"Software\Microsoft\Windows\CurrentVersion"


def source_hive(tmp_path, *, location="root", position="first", label="evidence"):
    bad = (PARENT + "\\" if location == "ancestor" else "") + "Unrelated"
    entries = [(path, [sz("Evidence", label + str(i))]) for i, path in enumerate(PATHS)]
    entries.insert(0 if position == "first" else len(entries), (bad, []))
    return write_hive(tmp_path, "NTUSER.DAT", entries), bad


def plugin_for(source):
    return BasePlugin(
        Registry.Registry(str(source)),
        logging.getLogger(__name__),
        "NTUSER.DAT",
        str(source),
    )


@pytest.mark.parametrize("location", ["root", "ancestor"])
@pytest.mark.parametrize("position", ["first", "last"])
def test_readable_fixed_paths_and_missing_sibling_share_one_diagnostic(
    tmp_path, location, position
):
    source, bad = source_hive(tmp_path, location=location, position=position)
    corrupt_name(source, key=bad)
    original = source.read_bytes()
    plugin = plugin_for(source)
    missing = (PARENT + "\\" if location == "ancestor" else "") + "Missing"

    # A missing key also traverses the unreadable name, irrespective of its order.
    assert plugin.open_key(missing) is None
    for _ in range(2):
        for i, path in enumerate(PATHS):
            assert plugin.open_key(path.swapcase()).value(
                "Evidence"
            ).value() == "evidence" + str(i)
        assert plugin.open_key(missing) is None

    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"
    assert plugin.errors[0]["error"].startswith("UnicodeDecodeError:")
    assert source.read_bytes() == original


@pytest.mark.parametrize("location", ["root", "ancestor"])
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_runner_preserves_all_run_records_after_name_failure(
    tmp_path, location, position, chunk_size
):
    source, bad = source_hive(tmp_path, location=location, position=position)
    baseline = reg2json(source, plugin_names=["run"])
    assert len(baseline) == 3
    corrupt_name(source, key=bad)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=["run"], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == baseline
    # A bad root name after Software is never touched by any native lookup.
    failures = 0 if (location, position) == ("root", "last") else 1
    assert runner.failed_records == failures
    if failures:
        assert runner.errors[0]["stage"] == "name"
        with pytest.raises(PartialExtractionError) as caught:
            reg2json(source, plugin_names=["run"], chunk_size=chunk_size)
        assert caught.value.records == baseline
        assert len(caught.value.diagnostics) == 1
    else:
        assert reg2json(source, plugin_names=["run"]) == baseline
    assert source.read_bytes() == original


@pytest.mark.parametrize("location", ["root", "ancestor"])
def test_strict_fixed_path_error_is_recorded_once(tmp_path, location):
    source, bad = source_hive(tmp_path, location=location)
    corrupt_name(source, key=bad)
    plugin = plugin_for(source)
    plugin.error_policy = "raise"

    with pytest.raises(UnicodeDecodeError):
        with plugin.recover(PATHS[0], stage="values"):
            plugin.open_key(PATHS[0])

    assert len(plugin.errors) == 1
    assert plugin.errors[0]["stage"] == "name"


def test_switching_to_strict_policy_does_not_reuse_continue_recovery(tmp_path):
    source, bad = source_hive(tmp_path)
    corrupt_name(source, key=bad)
    plugin = plugin_for(source)
    assert plugin.open_key(PATHS[0]) is not None
    plugin.error_policy = "raise"

    with pytest.raises(UnicodeDecodeError):
        plugin.open_key(PATHS[0])

    assert len(plugin.errors) == 2


def test_recovery_names_are_scoped_to_the_current_native_registry(tmp_path):
    sources = []
    for label in ("first", "second"):
        folder = tmp_path / label
        folder.mkdir()
        source, bad = source_hive(folder, label=label)
        corrupt_name(source, key=bad)
        sources.append(source)
    original = [source.read_bytes() for source in sources]
    plugin = plugin_for(sources[0])

    assert plugin.open_key(PATHS[0]).value("Evidence").value() == "first0"
    plugin.reg = Registry.Registry(str(sources[1]))
    plugin.hive_path = str(sources[1])
    assert plugin.open_key(PATHS[0]).value("Evidence").value() == "second0"
    assert len(plugin.errors) == 2
    assert [error["hive_path"] for error in plugin.errors] == list(map(str, sources))

    runner = Reg2es(sources, plugin_names=["run"])
    documents = [doc for chunk in runner.gen_records() for doc in chunk]
    assert [doc["reg2es"]["value_data"] for doc in documents] == [
        label + str(i) for label in ("first", "second") for i in range(3)
    ]
    assert runner.failed_records == 2
    assert [source.read_bytes() for source in sources] == original


@pytest.mark.parametrize(
    "path",
    [
        "",
        "Software",
        "software",
        "Software\\",
        "Software\\Microsoft\\",
        "Software\\Missing",
        "\\Software",
        "Software\\\\Microsoft",
        "Software\\Microsoft\\\\",
    ],
)
def test_healthy_native_open_semantics_and_fast_path(tmp_path, monkeypatch, path):
    source, _bad = source_hive(tmp_path)
    plugin = plugin_for(source)
    try:
        expected = plugin.reg.open(path).path()
    except Registry.RegistryKeyNotFoundException:
        expected = None
    monkeypatch.setattr(
        plugin, "read_subkeys", lambda key: pytest.fail("healthy open rescanned names")
    )

    key = plugin.open_key(path)

    assert (key.path() if key else None) == expected
    assert plugin.errors == []


@pytest.mark.parametrize(
    "path",
    [
        "Software\\",
        "Software\\Microsoft\\",
        "Software\\Missing",
        "\\Software",
        "Software\\\\Microsoft",
        "Software\\Microsoft\\\\",
    ],
)
def test_recovery_keeps_native_path_separator_semantics(tmp_path, path):
    source, bad = source_hive(tmp_path)
    native = Registry.Registry(str(source))
    try:
        expected = native.open(path).path()
    except Registry.RegistryKeyNotFoundException:
        expected = None
    corrupt_name(source, key=bad)
    plugin = plugin_for(source)

    key = plugin.open_key(path)

    assert (key.path() if key else None) == expected
    assert len(plugin.errors) == 1


def test_structural_errors_still_propagate_instead_of_being_treated_as_names(tmp_path):
    source, bad = source_hive(tmp_path)
    native = Registry.Registry(str(source))
    offset = native.open(bad)._nkrecord.offset()
    raw = bytearray(source.read_bytes())
    raw[offset : offset + 2] = b"??"
    source.write_bytes(raw)
    plugin = plugin_for(source)

    with pytest.raises(Registry.RegistryParse.ParseException):
        plugin.open_key(PATHS[0])

    assert plugin.errors == []
