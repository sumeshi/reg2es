"""Real Registry values remain recoverable across independent decode failures."""

from pathlib import Path
import logging
import runpy
import struct

import pytest
from Registry import Registry

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from reg2es.plugins.base import BasePlugin

MAKE_HIVE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github/artifact_fixture.py")
)["make_hive"]
BAD = b"a\0b\0c"
SIMPLE = {
    "recentdocs": (
        "NTUSER.DAT",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        3,
    ),
    "mstscmru": ("NTUSER.DAT", r"Software\Microsoft\Terminal Server Client\Default", 1),
    "mounteddevices": ("SYSTEM", "MountedDevices", 3),
    "printer_ports": ("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Ports", 1),
    "printer_history": ("NTUSER.DAT", r"Printers\ConvertUserDevModesCount", 1),
    "wordwheelquery": (
        "NTUSER.DAT",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        3,
    ),
    "env": ("NTUSER.DAT", "Environment", 1),
}


def branch(path, values=(), children=()):
    parts = path.split("\\")
    result = (parts[-1], list(children), list(values))
    for name in reversed(parts[:-1]):
        result = (name, [result], [])
    return result


def string(name, text):
    return name, 1, (text + "\0").encode("utf-16le")


def source(tmp_path, hive, tree):
    path = tmp_path / hive
    path.write_bytes(MAKE_HIVE(tree=tree))
    return path


def records(path, plugin, **kwargs):
    runner = Reg2es(path, plugin_names=[plugin], **kwargs)
    documents = [r for group in runner.gen_records() for r in group]
    return runner, documents


@pytest.mark.parametrize("plugin", SIMPLE)
@pytest.mark.parametrize("chunk", [1, 500])
def test_native_value_failure_does_not_drop_later_value(tmp_path, plugin, chunk):
    hive, path, kind = SIMPLE[plugin]
    values = [
        ("a", kind, "first\0".encode("utf-16le")),
        ("b", 7, BAD),
        ("c", kind, "last\0".encode("utf-16le")),
    ]
    hive_path = source(tmp_path, hive, [branch(path, values)])
    original = hive_path.read_bytes()
    runner, documents = records(hive_path, plugin, chunk_size=chunk)
    assert [r["registry"]["value"] for r in documents] == ["a", "c"]
    assert runner.successful_records == 2 and runner.failed_records == 1
    assert runner.errors[0]["value"] == "b"
    assert runner.errors[0]["key"].endswith(path)
    assert runner.errors[0]["stage"] == "record"
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(hive_path, plugin_names=[plugin], chunk_size=chunk)
    assert caught.value.records == documents
    assert hive_path.read_bytes() == original


@pytest.mark.parametrize("plugin", SIMPLE)
def test_native_strict_failure_is_recorded_once(tmp_path, plugin):
    hive, path, kind = SIMPLE[plugin]
    hive_path = source(tmp_path, hive, [branch(path, [("b", 7, BAD)])])
    runner = Reg2es(hive_path, plugin_names=[plugin], error_policy="raise")
    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())
    assert runner.failed_records == 1
    assert runner.errors[0]["value"] == "b"


@pytest.mark.parametrize("chunk", [1, 500])
def test_typed_url_bad_time_keeps_url_and_later_url(tmp_path, chunk):
    urls = [
        string("url" + str(i), "https://example.test/" + str(i)) for i in range(1, 4)
    ]
    times = [
        ("url1", 3, struct.pack("<Q", 133485408001234560)),
        ("url2", 7, BAD),
        ("url3", 3, struct.pack("<Q", 133485408001234560)),
    ]
    hive_path = source(
        tmp_path,
        "NTUSER.DAT",
        [
            branch(
                r"Software\Microsoft\Internet Explorer",
                children=[("TypedURLs", [], urls), ("TypedURLsTime", [], times)],
            )
        ],
    )
    runner, documents = records(hive_path, "typedurls", chunk_size=chunk)
    assert [r["registry"]["value"] for r in documents] == ["url1", "url2", "url3"]
    assert runner.failed_records == 1 and runner.errors[0]["stage"] == "timestamp"
    recovered = documents[1]
    assert recovered["reg2es"]["value_data"] == "https://example.test/2"
    assert recovered["reg2es"]["custom"]["typedurls_time_raw"] == BAD.hex()
    assert (
        recovered["reg2es"]["timestamp"]["fallback_reason"] == "invalid_typedurls_time"
    )


@pytest.mark.parametrize("plugin", ["sysinternals", "office_macros"])
def test_native_subkeys_and_programs_keep_later_records(tmp_path, plugin):
    if plugin == "sysinternals":
        tree = [
            branch(
                r"Software\Sysinternals",
                children=[
                    (
                        name,
                        [],
                        [
                            (
                                ("EulaAccepted", 7, BAD)
                                if name == "b"
                                else ("EulaAccepted", 4, struct.pack("<I", 1))
                            )
                        ],
                    )
                    for name in "abc"
                ],
            )
        ]
    else:
        raw = bytearray(24)
        struct.pack_into("<I", raw, 16, 20000000)
        raw[-4:] = b"\xff\xff\xff\x7f"
        entries = [("a", 3, raw), ("b", 7, BAD), ("c", 3, raw)]
        trust = branch(r"Word\Security\Trusted Documents\TrustRecords", entries)
        tree = [branch(r"Software\Microsoft\Office\16.0", children=[trust])]
    hive_path = source(tmp_path, "NTUSER.DAT", tree)
    runner, documents = records(hive_path, plugin)
    assert len(documents) == 2 and runner.failed_records == 1
    assert (
        documents[-1]["registry"].get("value", "") == "c"
        if plugin == "office_macros"
        else documents[-1]["registry"]["key"].endswith("c")
    )


@pytest.mark.parametrize("failed_field", ["ProxyEnable", "ProxyServer"])
def test_proxy_bad_field_does_not_drop_other_fields_or_autoconfig(
    tmp_path, failed_field
):
    values = [
        ("ProxyEnable", 4, struct.pack("<I", 1)),
        string("ProxyServer", "proxy.example:8080"),
        string("AutoConfigURL", "https://example.test/proxy.pac"),
    ]
    values = [
        (name, 7, BAD) if name == failed_field else (name, kind, data)
        for name, kind, data in values
    ]
    path = source(
        tmp_path,
        "NTUSER.DAT",
        [
            branch(
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", values
            )
        ],
    )
    runner, documents = records(path, "proxy")
    assert len(documents) == 2 and runner.failed_records == 1
    proxy, autoconfig = [r["reg2es"]["custom"] for r in documents]
    assert proxy["enabled" if failed_field == "ProxyEnable" else "proxy"] is None
    assert autoconfig["proxypac"] == "https://example.test/proxy.pac"


def test_software_environment_keeps_later_fields_and_handlers(tmp_path):
    tree = [
        branch(
            r"Microsoft\Windows",
            children=[
                (
                    "CurrentVersion",
                    [],
                    [
                        ("CommonFilesDir", 7, BAD),
                        string("ProgramFilesDir", r"C:\Programs"),
                    ],
                )
            ],
        ),
        branch(
            r"Microsoft\Windows NT\CurrentVersion",
            [string("SystemRoot", r"C:\Windows")],
        ),
    ]
    # Merge the Microsoft prefix once for a proper Registry key tree.
    tree = [("Microsoft", tree[0][1] + tree[1][1], [])]
    path = source(tmp_path, "SOFTWARE", tree)
    runner, documents = records(path, "env")
    assert [r["registry"]["value"] for r in documents] == [
        "ProgramFilesDir",
        "SystemRoot",
    ]
    assert runner.failed_records == 1 and runner.errors[0]["value"] == "CommonFilesDir"


def test_recover_preserves_keyboard_interrupt_and_nested_strict_diagnostics():
    plugin = BasePlugin(None, logging.getLogger(__name__), "SYSTEM", "fixture")
    with pytest.raises(KeyboardInterrupt):
        with plugin.recover("key"):
            raise KeyboardInterrupt()
    assert plugin.errors == []
    plugin.error_policy = "raise"
    with pytest.raises(ValueError):
        with plugin.recover("outer"):
            with plugin.recover("inner", "value"):
                raise ValueError("bad")
    assert len(plugin.errors) == 1 and plugin.errors[0]["key"] == "inner"
