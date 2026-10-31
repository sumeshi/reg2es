"""Native Registry coverage and independent-entry recovery regressions."""

from pathlib import Path
import runpy
import struct

import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es

MAKE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)["make_hive"]
BAD = ("broken", 7, b"a\0b\0c")


def sz(name, text):
    return name, 1, (text + "\0").encode("utf-16le")


def dword(name, value):
    return name, 4, struct.pack("<I", value)


def write_hive(tmp_path, hive, paths):
    root = {}
    for path, values in paths:
        node = root
        for component in path.split("\\"):
            node = node.setdefault(component, {"values": [], "children": {}})[
                "children"
            ]
        node[None] = values

    def children(node):
        return [
            (name, children(data["children"]), data["children"].get(None, []))
            for name, data in node.items()
            if name is not None
        ]

    source = tmp_path / hive
    source.write_bytes(MAKE(tree=children(root)))
    return source


def read_partial(source, plugin):
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=[plugin], chunk_size=1)
    records = [record for chunk in runner.gen_records() for record in chunk]
    assert runner.failed_records == 1
    assert runner.errors[0]["plugin"] == plugin
    assert runner.errors[0]["key"]
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=[plugin], chunk_size=500)
    assert caught.value.records == records
    assert len(caught.value.diagnostics) == 1
    strict = Reg2es(source, plugin_names=[plugin], error_policy="raise", chunk_size=1)
    with pytest.raises(Exception):
        list(strict.gen_records())
    assert strict.failed_records == 1
    assert source.read_bytes() == before
    return records, runner.errors[0]


@pytest.mark.parametrize("substitutes", [None, [], [sz("d000040c", "00001009")]])
def test_keyboard_substitutions_are_optional_and_decode_before_conversion(
    tmp_path, substitutes
):
    paths = [(r"Keyboard Layout\Preload", [sz("1", "d000040c")])]
    if substitutes is not None:
        paths.append((r"Keyboard Layout\Substitutes", substitutes))
    source = write_hive(tmp_path, "NTUSER.DAT", paths)
    records = reg2json(source, plugin_names=["keyboard"])
    assert len(records) == 1
    assert records[0]["reg2es"]["custom"]["substitute"] == (
        "00001009" if substitutes else None
    )


def test_keyboard_bad_substitution_keeps_readable_preload(tmp_path):
    source = write_hive(
        tmp_path,
        "NTUSER.DAT",
        [
            (r"Keyboard Layout\Preload", [sz("1", "d000040c"), sz("2", "00000409")]),
            (r"Keyboard Layout\Substitutes", [("d000040c", BAD[1], BAD[2])]),
        ],
    )
    records, diagnostic = read_partial(source, "keyboard")
    assert [record["registry"]["value"] for record in records] == ["1", "2"]
    assert all(record["reg2es"]["custom"]["substitute"] is None for record in records)
    assert diagnostic["value"] == "d000040c"


def test_uninstall_reads_both_views_and_recovers_later_programs(tmp_path):
    path = r"Microsoft\Windows\CurrentVersion\Uninstall"
    source = write_hive(
        tmp_path,
        "SOFTWARE",
        [
            (path + r"\a", [sz("DisplayName", "native first")]),
            (path + r"\b", [("DisplayName", BAD[1], BAD[2])]),
            (path + r"\c", [sz("DisplayName", "native last")]),
            ("Wow6432Node\\" + path + r"\d", [sz("DisplayName", "32-bit application")]),
        ],
    )
    records, _ = read_partial(source, "uninstall")
    assert [record["reg2es"]["custom"]["display_name"] for record in records] == [
        "native first",
        "[N/A]",
        "native last",
        "32-bit application",
    ]
    assert records[-1]["registry"]["key"].startswith("SOFTWARE\\Wow6432Node\\")


def test_portproxy_keeps_all_address_families_and_later_values(tmp_path):
    root = r"ControlSet001\Services\PortProxy"
    paths = [("Select", [dword("Current", 1)])]
    for family in ("v4tov4", "v4tov6", "v6tov4", "v6tov6"):
        values = [sz("before/443", "target/8443")]
        if family == "v4tov4":
            values.append(BAD)
        values.append(sz("after/443", "other/8443"))
        paths.append((root + "\\" + family + r"\tcp", values))
    paths.append((root + r"\v4tov4\udp", [sz("legacy/53", "target/53")]))
    source = write_hive(tmp_path, "SYSTEM", paths)
    records, _ = read_partial(source, "portproxy")
    assert len(records) == 9
    assert {record["registry"]["key"].split("\\")[-2] for record in records} == {
        "v4tov4",
        "v4tov6",
        "v6tov4",
        "v6tov6",
    }
    assert [record["reg2es"]["custom"]["proto"] for record in records].count("udp") == 1


def test_putty_reports_incomplete_session_and_recovers_later_session(tmp_path):
    root = r"Software\SimonTatham\PuTTY\Sessions"
    source = write_hive(
        tmp_path,
        "NTUSER.DAT",
        [
            (root + r"\a", [sz("HostName", "first.example"), sz("Protocol", "ssh")]),
            (root + r"\b", [sz("HostName", "incomplete.example")]),
            (root + r"\c", [sz("HostName", "last.example"), sz("Protocol", "ssh")]),
        ],
    )
    records, diagnostic = read_partial(source, "putty")
    assert [record["reg2es"]["custom"]["host"] for record in records] == [
        "first.example",
        "last.example",
    ]
    assert diagnostic["key"].endswith(r"\Sessions\b")


def test_putty_bad_host_key_does_not_suppress_saved_sessions(tmp_path):
    root = r"Software\SimonTatham\PuTTY"
    source = write_hive(
        tmp_path,
        "NTUSER.DAT",
        [
            (root + r"\SshHostKeys", [sz("badkey", "data"), sz("rsa@host", "key")]),
            (
                root + r"\Sessions\good",
                [sz("HostName", "example"), sz("Protocol", "ssh")],
            ),
        ],
    )
    records, diagnostic = read_partial(source, "putty")
    assert [record["reg2es"]["custom"]["type"] for record in records] == [
        "sshkey",
        "session",
    ]
    assert diagnostic["value"] == "badkey"


def test_usbstor_retains_instance_metadata_and_later_instances(tmp_path):
    root = r"ControlSet001\Enum\USBSTOR\Disk&Ven_Test"
    source = write_hive(
        tmp_path,
        "SYSTEM",
        [
            ("Select", [dword("Current", 1)]),
            (root + r"\a", [sz("FriendlyName", "first")]),
            (
                root + r"\b",
                [("FriendlyName", BAD[1], BAD[2]), sz("Serial", "retained")],
            ),
            (root + r"\c", [sz("FriendlyName", "last")]),
        ],
    )
    records, diagnostic = read_partial(source, "usbstor")
    assert [record["reg2es"]["custom"]["instance_id"] for record in records] == [
        "a",
        "b",
        "c",
    ]
    assert records[1]["reg2es"]["custom"]["registry_values"] == {"Serial": "retained"}
    assert diagnostic["value"] == "FriendlyName"


@pytest.mark.parametrize(
    "plugin,hive,paths,expected",
    [
        (
            "antivirus",
            "SOFTWARE",
            [
                (
                    r"Microsoft\Security Center\Provider\Av\a",
                    [
                        sz("DISPLAYNAME", "first"),
                        sz("PRODUCTEXE", "a"),
                        sz("REPORTINGEXE", "a"),
                        dword("STATE", 0),
                    ],
                ),
                (
                    r"Microsoft\Security Center\Provider\Av\b",
                    [("DISPLAYNAME", BAD[1], BAD[2])],
                ),
                (
                    r"Microsoft\Security Center\Provider\Av\c",
                    [
                        sz("DISPLAYNAME", "last"),
                        sz("PRODUCTEXE", "c"),
                        sz("REPORTINGEXE", "c"),
                        dword("STATE", 0),
                    ],
                ),
            ],
            2,
        ),
        (
            "kb",
            "SOFTWARE",
            [
                (
                    r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB1",
                    [dword("CurrentState", 0x70)],
                ),
                (
                    r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB2",
                    [("CurrentState", BAD[1], BAD[2])],
                ),
                (
                    r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB3",
                    [dword("CurrentState", 0x70)],
                ),
            ],
            2,
        ),
        (
            "lastloggedon",
            "SOFTWARE",
            [
                (
                    r"Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
                    [
                        sz("LastLoggedOnUser", "first"),
                        ("LastLoggedOnSAMUser", BAD[1], BAD[2]),
                        sz("LastLoggedOnDisplayName", "last"),
                    ],
                )
            ],
            2,
        ),
        (
            "rdphint",
            "NTUSER.DAT",
            [
                (
                    r"Software\Microsoft\Terminal Server Client\Servers\a",
                    [sz("UsernameHint", "first")],
                ),
                (
                    r"Software\Microsoft\Terminal Server Client\Servers\b",
                    [("UsernameHint", BAD[1], BAD[2])],
                ),
                (
                    r"Software\Microsoft\Terminal Server Client\Servers\c",
                    [sz("UsernameHint", "last")],
                ),
            ],
            3,
        ),
        (
            "systeminfo",
            "SOFTWARE",
            [
                (
                    r"Microsoft\Windows NT\CurrentVersion",
                    [
                        sz("RegisteredOwner", "first"),
                        ("InstallDate", BAD[1], BAD[2]),
                        sz("ProductName", "last"),
                    ],
                )
            ],
            2,
        ),
        (
            "teamviewer",
            "SOFTWARE",
            [
                ("TeamViewer", [("Always_Online", BAD[1], BAD[2])]),
                (
                    r"Wow6432Node\TeamViewer",
                    [
                        dword("Always_Online", 1),
                        dword("ClientID", 123),
                        sz("Version", "1"),
                    ],
                ),
            ],
            1,
        ),
    ],
)
def test_native_other_plugins_recover_independent_entries(
    tmp_path, plugin, hive, paths, expected
):
    source = write_hive(tmp_path, hive, paths)
    records, _ = read_partial(source, plugin)
    assert len(records) == expected


def test_native_kb_bad_optional_time_keeps_package_status(tmp_path):
    source = write_hive(
        tmp_path,
        "SOFTWARE",
        [
            (
                r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB1",
                [
                    dword("CurrentState", 0x70),
                    ("InstallTimeHigh", BAD[1], BAD[2]),
                    dword("InstallTimeLow", 1),
                ],
            )
        ],
    )
    records, diagnostic = read_partial(source, "kb")
    assert len(records) == 1
    assert records[0]["reg2es"]["custom"]["status"] == "Installed"
    assert diagnostic["value"] == "InstallTimeHigh"
    assert (
        records[0]["reg2es"]["timestamp"]["fallback_reason"]
        == "kb_install_time_unreadable"
    )


def test_native_teamviewer_bad_optional_startup_keeps_configuration(tmp_path):
    source = write_hive(
        tmp_path,
        "SOFTWARE",
        [
            (
                "TeamViewer",
                [
                    dword("Always_Online", 1),
                    dword("ClientID", 123),
                    sz("Version", "1"),
                    ("LastStartupTime", BAD[1], BAD[2]),
                ],
            )
        ],
    )
    records, diagnostic = read_partial(source, "teamviewer")
    assert len(records) == 1
    assert records[0]["reg2es"]["custom"]["ClientID"] == 123
    assert diagnostic["value"] == "LastStartupTime"


@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_bad_interface_name_does_not_discard_readable_siblings(
    tmp_path, chunk_size
):
    from Registry import Registry

    path = r"ControlSet001\Services\Tcpip\Parameters\Interfaces"
    source = write_hive(
        tmp_path,
        "SYSTEM",
        [
            ("Select", [dword("Current", 1)]),
            (path + r"\a", [sz("DhcpIPAddress", "192.0.2.1")]),
            (path + r"\b", [sz("DhcpIPAddress", "192.0.2.2")]),
            (path + r"\c", [sz("DhcpIPAddress", "192.0.2.3")]),
        ],
    )
    baseline = reg2json(source, plugin_names=["systeminfo"], chunk_size=chunk_size)
    key = Registry.Registry(str(source)).open(path + r"\b")
    offset = key._nkrecord.offset()
    payload = bytearray(source.read_bytes())
    flags = struct.unpack_from("<H", payload, offset + 2)[0]
    # Only the middle NK name is invalid; its allocated cell has enough padding.
    struct.pack_into("<H", payload, offset + 2, flags & ~0x20)
    struct.pack_into("<H", payload, offset + 0x48, 2)
    payload[offset + 0x4C : offset + 0x4E] = b"\x00\xd8"
    source.write_bytes(payload)
    original = source.read_bytes()
    native_keys = Registry.Registry(str(source)).open(path).subkeys()
    assert native_keys[0].name() == "a" and native_keys[2].name() == "c"
    with pytest.raises(UnicodeDecodeError):
        native_keys[1].name()

    runner = Reg2es(source, plugin_names=["systeminfo"], chunk_size=chunk_size)
    records = [record for chunk in runner.gen_records() for record in chunk]

    assert records == [
        record for record in baseline if not record["registry"]["key"].endswith(r"\b")
    ]
    assert runner.failed_records == 1
    assert runner.errors[0]["value"] == "DhcpIPAddress"
    assert runner.errors[0]["error"].startswith("UnicodeDecodeError:")
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["systeminfo"], chunk_size=chunk_size)
    assert caught.value.records == records
    strict = Reg2es(
        source, plugin_names=["systeminfo"], error_policy="raise", chunk_size=1
    )
    with pytest.raises(UnicodeDecodeError):
        list(strict.gen_records())
    assert strict.failed_records == 1
    assert source.read_bytes() == original
