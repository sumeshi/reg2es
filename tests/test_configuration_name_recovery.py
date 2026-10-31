"""Unreadable unrelated VK names leave supported configuration recoverable."""

import json
import struct

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from tests.test_other_plugin_recovery import dword, sz, write_hive


def configuration_hive(tmp_path, plugin, position, view="TeamViewer"):
    if plugin == "teamviewer":
        paths = [
            (
                view,
                [
                    dword("Always_Online", 1),
                    dword("ClientID", 1234),
                    sz("Version", "15.0"),
                    dword("LastStartupTime", 123),
                ],
            )
        ]
        hive, target = "SOFTWARE", view
    else:
        paths = [("Select", [dword("Current", 1)])]
        for name in "abc":
            paths.append(
                (
                    rf"ControlSet001\Services\{name}",
                    [
                        sz("ImagePath", rf"C:\Services\{name}.exe"),
                        dword("Start", 2),
                        sz("Description", "Service " + name),
                        sz("ObjectName", "LocalSystem"),
                    ],
                )
            )
        hive, target = "SYSTEM", r"ControlSet001\Services\b"
    values = next(values for path, values in paths if path == target)
    index = 0 if position == "first" else len(values)
    values.insert(index, sz("Unrelated", "ignored"))
    source = write_hive(tmp_path, hive, paths)
    return source, target, index


def damage_name(source, path, index):
    value = Registry.Registry(str(source)).open(path).values()[index]
    offset = value._vkrecord.offset()
    raw = bytearray(source.read_bytes())
    struct.pack_into("<H", raw, offset + 2, 2)
    struct.pack_into("<H", raw, offset + 16, 0)
    raw[offset + 20 : offset + 22] = b"\x00\xd8"
    source.write_bytes(raw)
    values = Registry.Registry(str(source)).open(path).values()
    with pytest.raises(UnicodeDecodeError):
        values[index].name()
    # All supported values remain independently readable on the native objects.
    assert all(
        value.name() and value.value() is not None
        for i, value in enumerate(values)
        if i != index
    )


@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("chunk_size", [1, 500])
@pytest.mark.parametrize(
    "plugin,view",
    [
        ("teamviewer", "TeamViewer"),
        ("teamviewer", r"Wow6432Node\TeamViewer"),
        ("services", None),
    ],
)
def test_bad_unrelated_name_preserves_configuration(
    tmp_path, plugin, view, position, chunk_size
):
    source, target, index = configuration_hive(tmp_path, plugin, position, view)
    baseline = reg2json(source, plugin_names=[plugin])
    assert len(baseline) == (1 if plugin == "teamviewer" else 3)
    damage_name(source, target, index)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == baseline
    assert runner.successful_records == len(baseline)
    assert runner.failed_records == 1
    assert len(runner.errors) == 1
    assert runner.errors[0]["plugin"] == plugin
    assert runner.errors[0]["key"].endswith(target)
    assert runner.errors[0]["stage"] == "name"
    assert runner.errors[0]["value"] is None
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=[plugin], chunk_size=chunk_size)
    assert caught.value.records == baseline
    assert len(caught.value.diagnostics) == 1
    assert source.read_bytes() == original


@pytest.mark.parametrize("plugin", ["teamviewer", "services"])
@pytest.mark.parametrize("position", ["first", "last"])
def test_strict_name_failure_is_reported_once(tmp_path, plugin, position):
    source, target, index = configuration_hive(tmp_path, plugin, position)
    damage_name(source, target, index)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], error_policy="raise", chunk_size=1)
    chunks = runner.gen_records()
    if plugin == "services":
        assert next(chunks)[0]["registry"]["key"].endswith(r"Services\a")

    with pytest.raises(UnicodeDecodeError):
        list(chunks)

    assert runner.failed_records == 1 and len(runner.errors) == 1
    assert runner.errors[0]["stage"] == "name"
    assert source.read_bytes() == original


def test_teamviewer_preserves_required_lookup_and_optional_presence_case(tmp_path):
    source = write_hive(
        tmp_path,
        "SOFTWARE",
        [
            (
                "TeamViewer",
                [
                    dword("ALWAYS_ONLINE", 1),
                    dword("clientid", 1234),
                    sz("VERSION", "15.0"),
                    dword("laststartuptime", 123),
                ],
            )
        ],
    )
    docs = reg2json(source, plugin_names=["teamviewer"])
    custom = docs[0]["reg2es"]["custom"]
    assert custom["AlwaysOnline"] is True and custom["ClientID"] == 1234
    assert custom["Version"] == "15.0" and custom["LastStartupTime"] == -1


def test_services_matches_lowercase_value_names_and_preserves_missing_defaults(tmp_path):
    source = write_hive(
        tmp_path,
        "SYSTEM",
        [
            ("Select", [dword("Current", 1)]),
            (
                r"ControlSet001\Services\example",
                [
                    sz("imagepath", "lower.exe"),
                    dword("start", 2),
                    sz("objectname", "NT AUTHORITY\\LocalService"),
                ],
            ),
        ],
    )
    docs = reg2json(source, plugin_names=["services"])
    assert docs[0]["reg2es"]["custom"] == {
        "image_path": "lower.exe",
        "start_mode": 2,
        "description": "N/A",
        "account": "NT AUTHORITY\\LocalService",
    }


def test_services_lowercase_values_are_exported_by_cli(tmp_path, run_cli):
    source = write_hive(
        tmp_path,
        "SYSTEM",
        [
            ("Select", [dword("Current", 1)]),
            (
                r"ControlSet001\Services\example",
                [sz("imagepath", "lower.exe"), dword("start", 3)],
            ),
        ],
    )
    output = tmp_path / "services.json"
    result = run_cli(
        "reg2json",
        [str(source), "--plugin", "services", "-o", str(output), "--quiet"],
    )
    assert result.returncode == 0, result.stderr
    records = json.loads(output.read_text())
    assert len(records) == 1
    custom = records[0]["reg2es"]["custom"]
    assert custom["image_path"] == "lower.exe"
    assert custom["start_mode"] == 3
    assert custom["description"] == "N/A"
    assert custom["account"] == "LocalSystem"


def test_teamviewer_missing_required_value_remains_a_reported_error(tmp_path):
    source = write_hive(
        tmp_path,
        "SOFTWARE",
        [
            (
                "TeamViewer",
                [
                    dword("Always_Online", 1),
                    sz("Version", "15.0"),
                ],
            )
        ],
    )
    runner = Reg2es(source, plugin_names=["teamviewer"], error_policy="raise")
    with pytest.raises(Registry.RegistryValueNotFoundException):
        list(runner.gen_records())
    assert runner.failed_records == 1 and len(runner.errors) == 1
