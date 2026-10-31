"""Native VK name failures leave independently readable plugin evidence intact."""

import struct

import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from tests.test_configuration_name_recovery import damage_name
from tests.test_other_plugin_recovery import dword, sz, write_hive

MRU_PATHS = {
    "runmru": r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "mndmru": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
    "filedialogmru": r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
}
PLUGINS = [
    *MRU_PATHS,
    "lastshutdown",
    "env",
    "compname",
    "antivirus",
    "kb",
    "putty",
    "gpo",
    "rdphint",
    "proxy",
    "keyboard",
]


def fixture_for(tmp_path, plugin, position):
    hive = "NTUSER.DAT"
    if plugin in MRU_PATHS:
        target = MRU_PATHS[plugin]
        paths = [(target, [sz("MRUList", "abc"), *[sz(n, n + ".exe") for n in "abc"]])]
    elif plugin == "lastshutdown":
        hive, target = "SYSTEM", r"ControlSet001\Control\Windows"
        paths = [(target, [("ShutdownTime", 3, struct.pack("<Q", 133485408000000000))])]
    elif plugin == "env":
        hive, target = "SOFTWARE", r"Microsoft\Windows\CurrentVersion"
        paths = [
            (
                target,
                [
                    sz(n, "C:\\" + n)
                    for n in (
                        "CommonFilesDir",
                        "CommonFilesDir (x86)",
                        "CommonW6432Dir",
                        "ProgramFilesDir",
                        "ProgramFilesDir (x86)",
                        "ProgramW6432Dir",
                    )
                ],
            )
        ]
    elif plugin == "compname":
        hive, target = "SYSTEM", r"ControlSet001\Control\ComputerName\ComputerName"
        paths = [(target, [sz("ComputerName", "EVIDENCE-HOST")])]
    elif plugin == "antivirus":
        hive = "SOFTWARE"
        root = r"Microsoft\Security Center\Provider\Av"
        target = root + r"\b"
        paths = [
            (
                root + "\\" + n,
                [
                    sz("DISPLAYNAME", n),
                    sz("PRODUCTEXE", n + ".exe"),
                    sz("REPORTINGEXE", n + ".exe"),
                    dword("STATE", 0),
                ],
            )
            for n in "abc"
        ]
    elif plugin == "kb":
        hive = "SOFTWARE"
        root = r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        target = root + r"\Package_for_KB2"
        paths = [
            (root + "\\Package_for_KB" + str(n), [dword("CurrentState", 0x70)])
            for n in (1, 2, 3)
        ]
    elif plugin == "putty":
        root = r"Software\SimonTatham\PuTTY\Sessions"
        target = root + r"\b"
        paths = [
            (root + "\\" + n, [sz("HostName", n + ".example"), sz("Protocol", "ssh")])
            for n in "abc"
        ]
    elif plugin == "gpo":
        hive = "SOFTWARE"
        root = r"Microsoft\Windows\CurrentVersion\Group Policy\History\ext"
        target = root + r"\b"
        paths = [
            (
                root + "\\" + n,
                [sz("DisplayName", n), sz("FileSysPath", "C:\\" + n), sz("GPOName", n)],
            )
            for n in "abc"
        ]
    elif plugin == "rdphint":
        root = r"Software\Microsoft\Terminal Server Client\Servers"
        target = root + r"\b"
        paths = [(root + "\\" + n, [sz("UsernameHint", n)]) for n in "abc"]
    elif plugin == "proxy":
        target = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        paths = [
            (
                target,
                [
                    dword("ProxyEnable", 1),
                    sz("ProxyServer", "proxy.example:8080"),
                    sz("ProxyOverride", "*.internal"),
                    sz("AutoConfigURL", "http://wpad/wpad.dat"),
                ],
            )
        ]
    elif plugin == "keyboard":
        target = r"Keyboard Layout\Substitutes"
        paths = [
            (r"Keyboard Layout\Preload", [sz("1", "d000040c")]),
            (target, [sz("d000040c", "00001009")]),
        ]
    else:
        raise AssertionError(plugin)
    if hive == "SYSTEM":
        paths.insert(0, ("Select", [dword("Current", 1)]))
    values = next(v for p, v in paths if p == target)
    index = 0 if position == "first" else len(values)
    values.insert(index, sz("Unrelated", "ignored"))
    return write_hive(tmp_path, hive, paths), target, index


@pytest.mark.parametrize("plugin", PLUGINS)
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_unreadable_unrelated_name_preserves_supported_values(
    tmp_path, plugin, position, chunk_size
):
    source, target, index = fixture_for(tmp_path, plugin, position)
    baseline = reg2json(source, plugin_names=[plugin])
    assert baseline
    damage_name(source, target, index)
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], chunk_size=chunk_size)

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == baseline
    assert runner.successful_records == len(baseline)
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"
    assert runner.errors[0]["key"].endswith(target)
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=[plugin], chunk_size=chunk_size)
    assert caught.value.records == baseline
    assert len(caught.value.diagnostics) == 1
    assert source.read_bytes() == original


@pytest.mark.parametrize("plugin", PLUGINS)
def test_strict_name_error_is_counted_once(tmp_path, plugin):
    source, target, index = fixture_for(tmp_path, plugin, "first")
    damage_name(source, target, index)
    runner = Reg2es(source, plugin_names=[plugin], error_policy="raise")

    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())

    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "name"


@pytest.mark.parametrize("plugin", MRU_PATHS)
def test_named_mru_entry_failure_keeps_other_ordered_entries(tmp_path, plugin):
    source, target, _ = fixture_for(tmp_path, plugin, "last")
    baseline = reg2json(source, plugin_names=[plugin])
    # MRUList still references b; b's data is intact but its name is unreadable.
    damage_name(source, target, 2)
    runner = Reg2es(source, plugin_names=[plugin])

    documents = [doc for chunk in runner.gen_records() for doc in chunk]

    assert documents == [doc for doc in baseline if doc["registry"]["value"] != "b"]
    # Count the observed name failure and unresolved ordered reference separately.
    assert runner.failed_records == 2
    assert [error["stage"] for error in runner.errors] == ["name", "record"]
    assert runner.errors[1]["value"] == "b"
