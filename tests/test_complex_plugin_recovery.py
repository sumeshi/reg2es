"""Native REGF entries recover at independent complex-plugin boundaries."""

from pathlib import Path
import runpy
import struct

import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es

ARTIFACT = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py")
)
BAD_STRING = b"a\0b\0c"
FILETIME = ARTIFACT["FILETIME"]


def string(name, value):
    return name, 1, (value + "\0").encode("utf-16le")


def nested(path, children=(), values=()):
    parts = path.split("\\")
    tree = [(parts[-1], list(children), list(values))]
    for part in reversed(parts[:-1]):
        tree = [(part, tree, [])]
    return tree


def action(command):
    def field(value):
        raw = value.encode("utf-16le")
        return struct.pack("<I", len(raw)) + raw

    return (
        b"\x03\x00"
        + field("Creator")
        + b"ff"
        + b"".join(field(value) for value in ("action", command, "", ""))
    )


def group(name):
    raw = name.encode("utf-16le")
    header = [0] * 13
    header[5] = len(raw)
    return struct.pack("<13L", *header) + raw


def fixture(tmp_path, plugin, broken=True, optional=False, enrichment=False):
    hive = "SOFTWARE"
    children = []
    for index, name in enumerate("abc"):
        bad = broken and name == "b"
        if plugin == "usersids":
            values = [
                (
                    ("ProfileImagePath", 7, BAD_STRING)
                    if bad
                    else string("ProfileImagePath", "C:\\Users\\" + name)
                )
            ]
        elif plugin == "srum":
            values = [("", 7, BAD_STRING) if bad else string("", name)]
        elif plugin == "gpo":
            values = [
                (
                    ("DisplayName", 7, BAD_STRING)
                    if bad and not optional
                    else string("DisplayName", name)
                ),
                string("FileSysPath", "C:\\Policies\\" + name),
                string("GPOName", name),
            ]
            if bad and optional:
                values.append(("DSPath", 7, BAD_STRING))
        elif plugin == "tasks":
            values = [
                string("Path", "\\" + name),
                ("Actions", 3, b"\x03\x00\x00\x00\x00\x00ffx" if bad else action(name)),
            ]
        elif plugin == "localgroups":
            name = f"{544 + index:08x}"
            values = [("C", 3, b"short" if bad else group(name))]
        elif plugin == "localusers":
            values = [("", 600 + index, b"")]
        else:
            raise AssertionError(plugin)
        children.append((name, [], values))

    if plugin == "usersids":
        tree = nested(r"Microsoft\Windows NT\CurrentVersion\ProfileList", children)
    elif plugin == "srum":
        tree = nested(r"Microsoft\Windows\CurrentVersion\SRUM\Extensions", children)
    elif plugin == "gpo":
        tree = nested(
            r"Microsoft\Windows\CurrentVersion\Group Policy\History",
            [("ext", children, [])],
        )
    elif plugin == "tasks":
        tree = nested(
            r"Microsoft\Windows NT\CurrentVersion",
            [("Schedule", [("TaskCache", [("Tasks", children, [])], [])], [])],
            [string("CurrentBuild", "19045")],
        )
    elif plugin == "localgroups":
        hive = "SAM"
        account_sid = struct.pack("<BB6s4L", 1, 4, b"\0\0\0\0\0\5", 21, 1, 2, 3)
        tree = nested(
            "SAM\\Domains",
            [
                ("Account", [], [("V", 3, b"short" if enrichment else account_sid)]),
                ("Builtin", [("Aliases", children, [])], []),
            ],
        )
    else:
        hive = "SAM"
        users = [("Names", children, [])]
        for index in range(3):
            raw = bytearray(80)
            struct.pack_into("<H", raw, 0, 2)
            struct.pack_into("<Q", raw, 8, FILETIME)
            struct.pack_into("<I", raw, 48, 600 + index)
            f_value = (
                ("F", 7, BAD_STRING) if broken and index == 1 else ("F", 3, bytes(raw))
            )
            users.append((f"{600 + index:08x}", [], [f_value]))
        tree = nested(r"SAM\Domains\Account\Users", users)
    source = tmp_path / hive
    source.write_bytes(ARTIFACT["make_hive"](tree=tree))
    return source


def read(source, plugin, policy="continue", chunk_size=500):
    runner = Reg2es(
        source, plugin_names=[plugin], error_policy=policy, chunk_size=chunk_size
    )
    records = [record for chunk in runner.gen_records() for record in chunk]
    return records, runner


@pytest.mark.parametrize(
    "plugin", ["usersids", "srum", "gpo", "tasks", "localusers", "localgroups"]
)
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_complex_failure_recovers_following_entry(tmp_path, plugin, chunk_size):
    source = fixture(tmp_path, plugin)
    original = source.read_bytes()
    records, runner = read(source, plugin, chunk_size=chunk_size)
    expected = 3 if plugin in ("tasks", "localusers") else 2
    assert len(records) == runner.successful_records == expected
    assert runner.failed_records == 1
    assert runner.errors[0]["key"] is not None
    assert runner.errors[0]["plugin"] == plugin
    assert source.read_bytes() == original
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=[plugin], chunk_size=chunk_size)
    assert caught.value.records == records
    assert len(caught.value.diagnostics) == 1
    if plugin == "tasks":
        middle = records[1]["reg2es"]["custom"]
        assert middle["Path"].endswith("\\b")
        assert middle["Actions"] == {"runas": None, "cmd": None}
        assert middle["Actions_raw"] == "030000000000666678"
    if plugin == "localusers":
        assert records[1]["reg2es"]["custom"]["sam_user"]["rid"] == 601
        assert records[1]["reg2es"]["custom"]["sam_user"]["f_raw"] == BAD_STRING.hex()
        assert (
            records[1]["reg2es"]["timestamp"]["fallback_reason"]
            == "sam_user_f_truncated"
        )
        assert runner.errors[0]["key"].endswith(r"Users\00000259")


@pytest.mark.parametrize(
    "plugin", ["usersids", "srum", "gpo", "tasks", "localusers", "localgroups"]
)
def test_native_complex_strict_records_once(tmp_path, plugin):
    source = fixture(tmp_path, plugin)
    runner = Reg2es(source, plugin_names=[plugin], error_policy="raise", chunk_size=1)
    chunks = runner.gen_records()
    assert len(next(chunks)) == 1
    with pytest.raises(Exception):
        next(chunks)
    assert list(chunks) == []
    assert runner.failed_records == 1


def test_native_bad_optional_gpo_field_keeps_gpo(tmp_path):
    source = fixture(tmp_path, "gpo", optional=True)
    records, runner = read(source, "gpo")
    assert len(records) == 3 and runner.failed_records == 1
    assert records[1]["reg2es"]["custom"]["DisplayName"] == "b"
    assert records[1]["reg2es"]["custom"]["DSPath"] == "N/A"
    assert runner.errors[0]["value"] == "DSPath"


def test_native_bad_group_enrichment_keeps_groups(tmp_path):
    source = fixture(tmp_path, "localgroups", broken=False, enrichment=True)
    records, runner = read(source, "localgroups")
    assert len(records) == 3 and runner.failed_records == 1


@pytest.mark.parametrize("field", ["Actions", "DynamicInfo"])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_task_getter_failure_preserves_raw_and_honors_policy(
    tmp_path, field, policy
):
    tasks = []
    for name in "abc":
        values = [string("Path", "\\" + name), ("Actions", 3, action(name))]
        if name == "b":
            values = [value for value in values if value[0] != field]
            values.append((field, 7, BAD_STRING))
        tasks.append((name, [], values))
    tree = nested(
        r"Microsoft\Windows NT\CurrentVersion",
        [("Schedule", [("TaskCache", [("Tasks", tasks, [])], [])], [])],
        [string("CurrentBuild", "19045")],
    )
    source = tmp_path / "SOFTWARE"
    source.write_bytes(ARTIFACT["make_hive"](tree=tree))
    original = source.read_bytes()
    runner = Reg2es(source, plugin_names=["tasks"], error_policy=policy, chunk_size=1)
    chunks = runner.gen_records()
    first = next(chunks)[0]
    assert first["reg2es"]["custom"]["Path"].endswith("\\a")
    if policy == "raise":
        with pytest.raises(UnicodeDecodeError):
            next(chunks)
    else:
        recovered = [row for chunk in chunks for row in chunk]
        assert len(recovered) == 2
        custom = recovered[0]["reg2es"]["custom"]
        raw = (
            custom["Actions_raw"]
            if field == "Actions"
            else custom["DynamicInfo"]["raw"]
        )
        assert raw == BAD_STRING.hex()
        assert custom["Path"].endswith("\\b")
        assert recovered[1]["reg2es"]["custom"]["Path"].endswith("\\c")
    assert runner.failed_records == 1
    assert runner.errors[0]["value"] == field
    assert source.read_bytes() == original


@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_auditpol_slot_failure_honors_policy(tmp_path, policy):
    raw = bytearray(12)
    struct.pack_into("<H", raw, 8, 18)
    raw.extend(struct.pack("<3H9H", 1, 9, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0))
    source = tmp_path / "SECURITY"
    source.write_bytes(
        ARTIFACT["make_hive"](
            tree=nested(r"Policy\PolAdtEv", values=[("", 3, bytes(raw))])
        )
    )
    runner = Reg2es(
        source, plugin_names=["auditpol"], error_policy=policy, chunk_size=1
    )
    chunks = runner.gen_records()
    first = next(chunks)[0]
    assert first["reg2es"]["custom"]["status"] == "Success"
    if policy == "raise":
        with pytest.raises(Exception, match="Unexpected value 9"):
            next(chunks)
    else:
        remaining = [row for chunk in chunks for row in chunk]
        assert len(remaining) == 1
        assert remaining[0]["reg2es"]["custom"]["status"] == "Failure"
        assert remaining[0]["reg2es"]["value_data"] == bytes(raw).hex()
    assert runner.failed_records == 1


@pytest.mark.parametrize("declared_count", [20, 65535])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_auditpol_count_cannot_read_footer_as_policies(
    tmp_path, declared_count, policy
):
    raw = bytearray(12)
    struct.pack_into("<H", raw, 8, 16)
    raw.extend(struct.pack("<2H9H", 1, 2, declared_count, 0, 0, 0, 0, 0, 0, 0, 0))
    source = tmp_path / "SECURITY"
    source.write_bytes(
        ARTIFACT["make_hive"](
            tree=nested(r"Policy\PolAdtEv", values=[("", 3, bytes(raw))])
        )
    )
    original = source.read_bytes()
    runner = Reg2es(
        source, plugin_names=["auditpol"], error_policy=policy, chunk_size=1
    )
    chunks = runner.gen_records()
    records = [next(chunks)[0], next(chunks)[0]]
    if policy == "raise":
        with pytest.raises(
            ValueError, match="truncated audit policy subcategory table"
        ):
            next(chunks)
    else:
        assert list(chunks) == []
    assert [row["reg2es"]["custom"]["status"] for row in records] == [
        "Success",
        "Failure",
    ]
    assert runner.successful_records == 2
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "subcategory:table"
    assert source.read_bytes() == original


@pytest.mark.parametrize(
    "footer_offset,truncate", [(0, False), (11, False), (40, False), (16, True)]
)
def test_native_auditpol_rejects_invalid_footer_boundary(
    tmp_path, footer_offset, truncate
):
    raw = bytearray(12)
    struct.pack_into("<H", raw, 8, footer_offset)
    raw.extend(struct.pack("<2H9H", 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0))
    if truncate:
        raw = raw[:-1]
    source = tmp_path / "SECURITY"
    source.write_bytes(
        ARTIFACT["make_hive"](
            tree=nested(r"Policy\PolAdtEv", values=[("", 3, bytes(raw))])
        )
    )
    records, runner = read(source, "auditpol")
    assert records == [] and runner.failed_records == 1
    assert (
        "invalid audit policy subcategory footer boundary" in runner.errors[0]["error"]
    )
