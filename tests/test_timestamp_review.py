"""Independent regression checks for artifact time selection."""

from datetime import datetime, timezone
import importlib
import logging
import os
import struct
import time

import orjson
import pytest
from Registry.Registry import RegBin, RegSZ

from reg2es.models.Reg2es import plugin_result_to_document
from reg2es.plugins.base import PluginResult
from reg2es.plugins.lastshutdown import Plugin as ShutdownPlugin
from reg2es.plugins.kb import Plugin as KBPlugin
from reg2es.plugins.localusers import Plugin as UsersPlugin
from reg2es.plugins.office_macros import Plugin as OfficePlugin
from reg2es.plugins.typedurls import Plugin as TypedURLsPlugin
from reg2es.plugins.userassist import Plugin as UserAssistPlugin
from tests.regrippy.reg_mock import RegistryKeyMock, RegistryMock, RegistryValueMock

FILETIME = 133485408001234560  # 2024-01-01 00:00:00.123456 UTC


def document(result, plugin, hive):
    return plugin_result_to_document(result, plugin, hive, "-")


@pytest.mark.parametrize("length, offset", [(16, 8), (72, 60)])
def test_userassist_filetime_submicrosecond_uses_shared_integer_conversion(
    length, offset
):
    key = RegistryKeyMock.build(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    )
    raw = bytearray(length)
    struct.pack_into("<Q", raw, offset, FILETIME + 7)
    key.add_value(RegistryValueMock("grfg.rkr", bytes(raw), RegBin))
    registry = RegistryMock("NTUSER.DAT", "ntuser", key.root())
    results = list(
        UserAssistPlugin(registry, logging.getLogger(__name__), "NTUSER.DAT", "-").run()
    )
    doc = document(results[0], "userassist", "NTUSER.DAT")
    assert doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    assert doc["reg2es"]["timestamp"]["raw"] == str(FILETIME + 7)


@pytest.mark.parametrize("raw", [b"short", b"\x00" * 8, b"\xff" * 8])
def test_shutdown_invalid_time_keeps_record_and_raw_value(raw):
    key = RegistryKeyMock.build(r"ControlSet001\Control\Windows")
    key.add_value(RegistryValueMock("ShutdownTime", raw, RegBin))
    registry = RegistryMock("SYSTEM", "system", key.root())
    registry.set_ccs(1)
    results = list(
        ShutdownPlugin(registry, logging.getLogger(__name__), "SYSTEM", "-").run()
    )
    assert len(results) == 1
    doc = document(results[0], "lastshutdown", "SYSTEM")
    assert doc["reg2es"]["timestamp"]["source"] == "key.last_write"
    assert doc["reg2es"]["value_data"] == raw.hex()
    orjson.dumps(doc)


def test_typedurls_uses_sibling_key_case_insensitive_value_matching():
    key = RegistryKeyMock.build(r"Software\Microsoft\Internet Explorer\TypedURLs")
    parent = key.root().open(r"Software\Microsoft\Internet Explorer")
    times = RegistryKeyMock("TypedURLsTime", parent)
    parent.add_child(times)
    key.add_value(RegistryValueMock("url1", "https://example.org", RegSZ))
    times.add_value(RegistryValueMock("URL1", struct.pack("<Q", FILETIME), RegBin))
    registry = RegistryMock("NTUSER.DAT", "ntuser", key.root())
    results = list(
        TypedURLsPlugin(registry, logging.getLogger(__name__), "NTUSER.DAT", "-").run()
    )
    assert len(results) == 1
    doc = document(results[0], "typedurls", "NTUSER.DAT")
    assert doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    assert doc["reg2es"]["value_data"] == "https://example.org"
    orjson.dumps(doc)


def sam_results(data):
    user = RegistryKeyMock.build(r"SAM\Domains\Account\Users\Names\Alice")
    user.add_value(RegistryValueMock("", b"", 500))
    users = user.root().open(r"SAM\Domains\Account\Users")
    rid_key = RegistryKeyMock("000001F4", users)
    users.add_child(rid_key)
    rid_key.add_value(RegistryValueMock("F", data, RegBin))
    registry = RegistryMock("SAM", "sam", user.root())
    return list(
        UsersPlugin(registry, logging.getLogger(__name__), "SAM", "/evidence/SAM").run()
    )


def sam_f_data(*, revision=3, rid=500, length=80):
    data = bytearray(length)
    struct.pack_into("<H", data, 0, revision)
    struct.pack_into("<Q", data, 8, FILETIME)
    struct.pack_into("<Q", data, 24, FILETIME)
    struct.pack_into("<Q", data, 32, 0x7FFFFFFFFFFFFFFF)
    struct.pack_into("<I", data, 48, rid)
    return bytes(data)


def test_sam_rid_is_value_type_and_expiry_sentinel_does_not_drop_user():
    results = sam_results(sam_f_data())
    assert len(results) == 1
    doc = document(results[0], "localusers", "SAM")
    assert doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    orjson.dumps(doc)


@pytest.mark.parametrize(
    "params,reason",
    [
        ({"length": 52}, "sam_user_f_truncated"),
        ({"length": 79}, "sam_user_f_truncated"),
        ({"length": 81}, "sam_user_f_unsupported_size"),
        ({"revision": 2}, "sam_user_f_unsupported_revision"),
        ({"revision": 0xFFFF}, "sam_user_f_unsupported_revision"),
        ({"rid": 501}, "sam_user_rid_mismatch"),
    ],
)
def test_sam_unverified_structure_preserves_raw_and_never_adopts_times(
    params, reason, caplog
):
    raw = sam_f_data(**params)
    results = sam_results(raw)
    assert len(results) == 1
    doc = document(results[0], "localusers", "SAM")
    assert doc["reg2es"]["timestamp"]["source"] == "key.last_write"
    assert doc["reg2es"]["timestamp"]["fallback_reason"] == reason
    custom = doc["reg2es"]["custom"]["sam_user"]
    assert custom["f_raw"] == raw.hex()
    assert all(
        custom[field] is None
        for field in ("last_login", "password_reset", "account_expiry", "failed_login")
    )
    assert "plugin=localusers" in caplog.text and "/evidence/SAM" in caplog.text
    orjson.dumps(doc)


@pytest.mark.parametrize(
    "parts", [{}, {"high": FILETIME >> 32}, {"low": FILETIME & 0xFFFFFFFF}]
)
def test_kb_missing_parts_preserve_the_other_value_without_warning(parts, caplog):
    key = RegistryKeyMock.build(
        r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB123456"
    )
    key.add_value(RegistryValueMock("CurrentState", 0x70, 4))
    for part, value in parts.items():
        key.add_value(RegistryValueMock("InstallTime" + part.title(), value, 4))
    registry = RegistryMock("SOFTWARE", "software", key.root())
    results = list(
        KBPlugin(registry, logging.getLogger(__name__), "SOFTWARE", "-").run()
    )
    assert len(results) == 1
    doc = document(results[0], "kb", "SOFTWARE")
    assert doc["reg2es"]["timestamp"]["source"] == "key.last_write"
    assert doc["reg2es"]["timestamp"]["fallback_reason"] == "kb_install_time_missing"
    assert doc["reg2es"]["custom"]["install_time_raw"] == {
        part: parts.get(part) for part in ("high", "low")
    }
    assert not caplog.records


def test_kb_out_of_range_filetime_keeps_package():
    key = RegistryKeyMock.build(
        r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB123456"
    )
    for name, value in (
        ("CurrentState", 0x70),
        ("InstallTimeHigh", 0xFFFFFFFF),
        ("InstallTimeLow", 0xFFFFFFFF),
    ):
        key.add_value(RegistryValueMock(name, value, 4))
    registry = RegistryMock("SOFTWARE", "software", key.root())
    results = list(
        KBPlugin(registry, logging.getLogger(__name__), "SOFTWARE", "-").run()
    )
    assert len(results) == 1
    assert (
        document(results[0], "kb", "SOFTWARE")["reg2es"]["timestamp"]["source"]
        == "key.last_write"
    )


def test_office_uses_enabled_time_not_document_creation_time():
    # Published observed TrustRecord: creation 22:01:06; macros enabled 22:03.
    # https://github.com/fox-it/dissect.target/blob/main/tests/plugins/os/windows/regf/test_trusteddocs.py
    key = RegistryKeyMock.build(
        r"Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords"
    )
    raw = bytes.fromhex("5AAC70BDC995DA010028A153C5FFFFFFABDEB301FFFFFF7F")
    key.add_value(RegistryValueMock("example.docm", raw, RegBin))
    registry = RegistryMock("NTUSER.DAT", "ntuser", key.root())
    results = list(
        OfficePlugin(registry, logging.getLogger(__name__), "NTUSER.DAT", "-").run()
    )
    assert len(results) == 1
    doc = document(results[0], "office_macros", "NTUSER.DAT")
    assert doc["@timestamp"] == "2024-04-23T22:03:00Z"
    assert doc["reg2es"]["value_data"] == raw.hex()


def test_tasks_selects_one_representative_time_and_keeps_others_in_custom():
    from reg2es.plugins.tasks import Plugin as TasksPlugin

    version = RegistryKeyMock.build(r"Microsoft\Windows NT\CurrentVersion")
    registry = RegistryMock("SOFTWARE", "software", version.root())
    version.add_value(RegistryValueMock("CurrentBuild", "7601", RegSZ))

    schedule = RegistryKeyMock("Schedule", version)
    version.add_child(schedule)
    taskcache = RegistryKeyMock("TaskCache", schedule)
    schedule.add_child(taskcache)
    tasks = RegistryKeyMock("Tasks", taskcache)
    taskcache.add_child(tasks)
    plain = RegistryKeyMock("Plain", taskcache)
    taskcache.add_child(plain)

    guid = "{11111111-2222-3333-4444-555555555555}"
    task = RegistryKeyMock(guid, tasks)
    tasks.add_child(task)
    plain_guid = RegistryKeyMock(guid, plain)
    plain.add_child(plain_guid)

    # DynamicInfo (28 bytes): created at 4, last start at 12.
    dynamic = bytearray(28)
    struct.pack_into("<Q", dynamic, 4, FILETIME - 3_600_000_000_000_000)
    struct.pack_into("<Q", dynamic, 12, FILETIME)
    task.add_value(RegistryValueMock("DynamicInfo", bytes(dynamic), RegBin))
    task.add_value(RegistryValueMock("Path", "\\Example", RegSZ))

    results = list(
        TasksPlugin(registry, logging.getLogger(__name__), "SOFTWARE", "-").run()
    )
    assert len(results) == 1
    doc = document(results[0], "tasks", "SOFTWARE")
    assert doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    assert doc["reg2es"]["timestamp"]["source"] == "TaskCache.DynamicInfo.last_start"
    # The non-representative candidate stays in custom, not in a second document.
    assert (
        doc["reg2es"]["custom"]["DynamicInfo"]["created"]
        == FILETIME - 3_600_000_000_000_000
    )
    assert doc["reg2es"]["custom"]["DynamicInfo"]["last_start"] == FILETIME


def test_event_time_metadata_is_json_serializable_and_mapping_stable():
    records = []
    for raw in (FILETIME, b"\x00\x01", datetime(2024, 1, 1, tzinfo=timezone.utc)):
        result = PluginResult()
        result.mtime = 1.5
        result.set_event_time(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            source="test",
            meaning="test",
            raw=raw,
        )
        doc = document(result, "test", "SYSTEM")
        serialized = orjson.loads(orjson.dumps(doc))
        records.append(serialized["reg2es"]["timestamp"])
    # A single Elasticsearch field must not alternate between numeric and
    # string values according to the originating plugin.
    raw_values = [record["raw"] for record in records if "raw" in record]
    assert not raw_values or all(isinstance(value, str) for value in raw_values)


@pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="requires POSIX timezone switching"
)
def test_naive_registry_lastwrite_is_utc_regardless_of_host_timezone(monkeypatch):
    key = RegistryKeyMock.build("Example")
    key.timestamp = lambda: datetime(2024, 1, 1, microsecond=123456)
    original = os.environ.get("TZ")
    try:
        for zone in ("UTC0", "JST-9", "EST5"):
            monkeypatch.setenv("TZ", zone)
            time.tzset()
            doc = document(PluginResult(key=key), "regtime", "SYSTEM")
            assert doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    finally:
        if original is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", original)
        time.tzset()


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
@pytest.mark.parametrize("split", [False, True])
def test_timestamp_survives_json_exports_and_es_bulk(
    tmp_path, monkeypatch, output_format, split
):
    json_module = importlib.import_module("reg2es.presenters.Reg2jsonPresenter")
    es_module = importlib.import_module("reg2es.models.ElasticsearchUtils")
    result = PluginResult()
    result.mtime = 100
    result.set_event_time(
        datetime(2024, 1, 1, microsecond=123456, tzinfo=timezone.utc),
        source="ShutdownTime",
        meaning="shutdown",
        raw=FILETIME,
    )
    expected = document(result, "lastshutdown", "SYSTEM")

    class Runner:
        def __init__(self, **kwargs):
            pass

        def gen_records(self):
            yield [expected]

        def close(self):
            pass

    monkeypatch.setattr(json_module, "Reg2es", Runner)
    output = tmp_path / ("split" if split else "export.json")
    presenter = json_module.Reg2jsonPresenter(
        "SYSTEM",
        output_path=str(output),
        is_quiet=True,
        split=split,
        output_format=output_format,
    )
    paths = presenter.export_json()
    payload = orjson.loads(paths[0].read_bytes())
    exported = payload if output_format == "jsonl" else payload[0]
    captured = []

    def bulk(client, actions, **kwargs):
        captured.extend(actions)
        return len(captured), []

    monkeypatch.setattr(es_module, "bulk", bulk)
    client = es_module.ElasticsearchUtils.__new__(es_module.ElasticsearchUtils)
    client.es = object()
    assert client.bulk_indice([expected], "registry") == (1, [])
    assert exported == captured[0]["_source"] == expected


def test_systeminfo_mixes_time_bearing_and_plain_rows():
    from reg2es.plugins.systeminfo import Plugin as SystemInfoPlugin

    host_name = RegistryKeyMock.build(
        r"ControlSet001\Control\ComputerName\ComputerName"
    )
    registry = RegistryMock("SYSTEM", "system", host_name.root())
    registry.set_ccs(1)
    host_name.add_value(RegistryValueMock("ComputerName", "TestPC", RegSZ))

    control = registry.open(r"ControlSet001\Control")
    windows = RegistryKeyMock("Windows", control)
    control.add_child(windows)
    windows.add_value(
        RegistryValueMock("ShutdownTime", struct.pack("<Q", FILETIME + 7), RegBin)
    )

    results = list(
        SystemInfoPlugin(registry, logging.getLogger(__name__), "SYSTEM", "-").run()
    )
    docs = [document(result, "systeminfo", "SYSTEM") for result in results]

    assert len(docs) == 2
    by_value = {doc["reg2es"]["custom"]["value"]: doc for doc in docs}
    hostname_doc = next(
        doc for doc in docs if doc["reg2es"]["custom"]["value"].startswith("Hostname")
    )
    shutdown_doc = next(
        doc
        for doc in docs
        if doc["reg2es"]["custom"]["value"].startswith("Last Shutdown Time")
    )
    assert hostname_doc["@timestamp"] != shutdown_doc["@timestamp"]
    assert hostname_doc["reg2es"]["timestamp"]["source"] == "key.last_write"
    assert shutdown_doc["reg2es"]["timestamp"]["source"] == "ShutdownTime"
    assert shutdown_doc["@timestamp"] == "2024-01-01T00:00:00.123456Z"
    orjson.dumps(by_value)


def test_document_count_and_custom_fields_preserved_with_artifact_time():
    from reg2es.plugins.kb import Plugin as KBPlugin

    packages = RegistryKeyMock.build(
        r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    )
    for index in range(3):
        key = RegistryKeyMock(f"Package_for_KB{index}", packages)
        packages.add_child(key)
        key.add_value(RegistryValueMock("CurrentState", 0x70, 4))
        key.add_value(RegistryValueMock("DisplayName", f"Update {index}", RegSZ))
        key.add_value(RegistryValueMock("InstallTimeHigh", (FILETIME >> 32), 4))
        key.add_value(RegistryValueMock("InstallTimeLow", (FILETIME & 0xFFFFFFFF), 4))

    registry = RegistryMock("SOFTWARE", "software", packages.root())
    results = list(
        KBPlugin(registry, logging.getLogger(__name__), "SOFTWARE", "-").run()
    )
    assert len(results) == 3
    docs = [document(result, "kb", "SOFTWARE") for result in results]
    assert all(doc["@timestamp"] == "2024-01-01T00:00:00.123456Z" for doc in docs)
    assert sorted(doc["reg2es"]["custom"]["kb"] for doc in docs) == [
        "KB0",
        "KB1",
        "KB2",
    ]
    assert all(doc["reg2es"]["custom"]["status_code"] == 0x70 for doc in docs)
    for doc in docs:
        assert doc["reg2es"]["timestamps"]["modified"] != 0
        assert doc["reg2es"]["timestamp"]["source"] == "InstallTimeHigh/InstallTimeLow"
        orjson.dumps(doc)
