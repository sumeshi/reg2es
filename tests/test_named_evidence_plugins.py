"""Native name failures leave independently readable evidence recoverable."""

import struct

import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from tests.test_complex_plugin_recovery import FILETIME, group
from tests.test_configuration_name_recovery import damage_name
from tests.test_office_name_recovery import office_hive
from tests.test_other_plugin_recovery import dword, sz, write_hive
from tests.test_shimcache_unicode import cache_with_paths
from tests.test_task_name_recovery import corrupt_name

CASES = (
    "uninstall",
    "srum",
    "sysinternals",
    "timezone",
    "version",
    "shimcache",
    "tasks",
    "auditpol",
    "localgroups",
    "localusers",
    "office_macros",
    "userassist",
)


def evidence_case(tmp_path, plugin, position):
    if plugin == "office_macros":
        source = office_hive(
            tmp_path, versions=("16.0",), programs=("Word", "Excel", "PowerPoint")
        )
        program = "Word" if position == "first" else "PowerPoint"
        key = rf"Software\Microsoft\Office\16.0\{program}"
        baseline = reg2json(source, plugin_names=[plugin])
        expected = [
            doc for doc in baseline if f"\\{program}\\" not in doc["registry"]["key"]
        ]
        return source, lambda: corrupt_name(source, key=key), expected

    paths = []
    hive = "SOFTWARE"
    if plugin == "uninstall":
        target = r"Microsoft\Windows\CurrentVersion\Uninstall\example"
        values = [
            sz("DisplayName", "Example"),
            sz("UninstallString", "remove.exe"),
            sz("InstallDate", "20261030"),
        ]
    elif plugin == "srum":
        target = r"Microsoft\Windows\CurrentVersion\SRUM\Extensions\example"
        values = [sz("", "Example extension")]
    elif plugin == "sysinternals":
        hive, target = "NTUSER.DAT", r"Software\Sysinternals\PsExec"
        values = [dword("EulaAccepted", 1)]
    elif plugin == "timezone":
        hive, target = "SYSTEM", r"ControlSet001\Control\TimeZoneInformation"
        values = [sz("TimeZoneKeyName", "Tokyo Standard Time")]
    elif plugin == "version":
        target = r"Microsoft\Windows NT\CurrentVersion"
        values = [sz("ProductName", "Windows 11 Pro")]
    elif plugin == "shimcache":
        hive, target = "SYSTEM", r"ControlSet001\Control\Session Manager\AppCompatCache"
        cache = cache_with_paths(
            "win10", [p.encode("utf-16le") for p in (r"C:\first.exe", r"C:\last.exe")]
        )
        values = [("AppCompatCache", 3, cache)]
    elif plugin == "tasks":
        target = r"Microsoft\Windows NT\CurrentVersion"
        values = [sz("CurrentBuild", "19045")]
        paths.extend(
            (
                target + r"\Schedule\TaskCache\Tasks" + "\\" + name,
                [sz("Path", "\\" + name)],
            )
            for name in "abc"
        )
    elif plugin == "auditpol":
        hive, target = "SECURITY", r"Policy\PolAdtEv"
        raw = bytearray(12)
        struct.pack_into("<H", raw, 8, 18)
        raw.extend(struct.pack("<3H", 1, 2, 3))
        raw.extend(struct.pack("<9H", 3, 0, 0, 0, 0, 0, 0, 0, 0))
        values = [("", 3, bytes(raw))]
    elif plugin == "localgroups":
        hive = "SAM"
        sid = struct.pack("<BB6s4L", 1, 4, b"\0\0\0\0\0\5", 21, 1, 2, 3)
        paths.append((r"SAM\Domains\Account", [("V", 3, sid)]))
        root = r"SAM\Domains\Builtin\Aliases"
        for rid in (544, 545, 546):
            paths.append((root + f"\\{rid:08x}", [("C", 3, group(str(rid)))]))
        target = root + r"\00000221"
        values = next(values for path, values in paths if path == target)
    elif plugin == "localusers":
        hive, root = "SAM", r"SAM\Domains\Account\Users"
        for rid in (600, 601, 602):
            raw = bytearray(80)
            struct.pack_into("<H", raw, 0, 2)
            struct.pack_into("<Q", raw, 8, FILETIME)
            struct.pack_into("<I", raw, 48, rid)
            paths.extend(
                [
                    (root + f"\\Names\\user{rid}", [("", rid, b"")]),
                    (root + f"\\{rid:08x}", [("F", 3, bytes(raw))]),
                ]
            )
        target = root + r"\00000259"
        values = next(values for path, values in paths if path == target)
    else:
        assert plugin == "userassist"
        hive = "NTUSER.DAT"
        target = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
        raw = bytearray(72)
        struct.pack_into("<I", raw, 4, 3)
        struct.pack_into("<Q", raw, 60, FILETIME)
        paths = [(target + r"\Count", [("pnyphygbe.rkr", 3, bytes(raw))])]
        paths.insert(
            0 if position == "first" else len(paths), (target + r"\Unrelated", [])
        )
        source = write_hive(tmp_path, hive, paths)
        baseline = reg2json(source, plugin_names=[plugin])
        return (
            source,
            lambda: corrupt_name(source, key=target + r"\Unrelated"),
            baseline,
        )

    if hive == "SYSTEM":
        paths.insert(0, ("Select", [dword("Current", 1)]))
    index = 0 if position == "first" else len(values)
    values.insert(index, sz("Unrelated", "ignored"))
    if not any(path == target for path, _values in paths):
        paths.append((target, values))
    source = write_hive(tmp_path, hive, paths)
    baseline = reg2json(source, plugin_names=[plugin])
    assert baseline
    return source, lambda: damage_name(source, target, index), baseline


@pytest.mark.parametrize("plugin", CASES)
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_unreadable_name_keeps_supported_evidence(
    tmp_path, plugin, position, chunk_size
):
    source, damage, expected = evidence_case(tmp_path, plugin, position)
    damage()
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == expected
    assert runner.successful_records == len(expected)
    assert runner.failed_records == 1
    assert runner.errors[0]["plugin"] == plugin
    assert runner.errors[0]["stage"] == "name"
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=[plugin], chunk_size=chunk_size)
    assert caught.value.records == expected
    assert len(caught.value.diagnostics) == 1
    assert source.read_bytes() == before


@pytest.mark.parametrize("plugin", CASES)
@pytest.mark.parametrize("position", ["first", "last"])
def test_strict_name_failure_is_reported_once(tmp_path, plugin, position):
    source, damage, _expected = evidence_case(tmp_path, plugin, position)
    damage()
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], error_policy="raise", chunk_size=1)

    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())

    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    assert source.read_bytes() == before
