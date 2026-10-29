"""Native-hive regressions for cache recovery and retained registry evidence."""

import hashlib
from pathlib import Path
import runpy
import struct

import orjson
import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.Reg2es import Reg2es
from reg2es.plugins import shimcache
from tests.test_shimcache_entries import FILETIME, _winxp_cache, _winxp_entry

FIXTURE_MODULE = Path(__file__).resolve().parents[1] / ".github" / "artifact_fixture.py"


def _write_hive(tmp_path, cache):
    make_hive = runpy.run_path(str(FIXTURE_MODULE))["make_hive"]
    values = [("AppCompatCache", 3, cache)]
    leaf = ("AppCompatCache", [], values)
    manager = ("Session Manager", [leaf], [])
    control = ("Control", [manager], [])
    tree = [
        ("Select", [], [("Current", 4, struct.pack("<I", 1))]),
        ("ControlSet001", [control], []),
    ]
    destination = tmp_path / "SYSTEM"
    destination.write_bytes(make_hive(tree=tree))
    return destination


def _read_native(tmp_path, cache, *, policy="continue", chunk_size=500):
    source = _write_hive(tmp_path, cache)
    original = source.read_bytes()
    runner = Reg2es(
        source,
        plugin_names=["shimcache"],
        error_policy=policy,
        chunk_size=chunk_size,
    )
    try:
        documents = [doc for chunk in runner.gen_records() for doc in chunk]
    finally:
        runner.close()
        assert source.read_bytes() == original
    return documents, runner


def _modern_cache(format_name, bodies):
    if format_name == "win8":
        start, magic = shimcache.WIN8_STATS_SIZE, shimcache.WIN8_MAGIC
    elif format_name == "win81":
        start, magic = shimcache.WIN8_STATS_SIZE, shimcache.WIN81_MAGIC
    elif format_name == "win10":
        start, magic = shimcache.WIN10_STATS_SIZE, shimcache.WIN10_MAGIC
    else:
        start, magic = shimcache.WIN10_CREATORS_STATS_SIZE, shimcache.WIN10_MAGIC
    return bytes(start) + b"".join(
        struct.pack("<4sLL", magic, 0, len(body)) + body for body in bodies
    )


def _modern_body(format_name, path):
    encoded = path.encode("utf-16le")
    body = struct.pack("<H", len(encoded)) + encoded
    if format_name in ("win8", "win81"):
        return body + struct.pack("<HLLQ L", 0, 0, 0, FILETIME, 0)
    return body + struct.pack("<Q", FILETIME)


def test_default_binary_fixture_is_unchanged():
    data = runpy.run_path(str(FIXTURE_MODULE))["make_hive"]()
    assert hashlib.sha256(data).hexdigest() == (
        "f8dd7c23682ebb00a5ea9fb72357680d4c20dec529b0f65fbe0bf3694e742781"
    )


@pytest.mark.parametrize("path", [r"C:\一.exe", r"C:\あ", "C:\\emoji😀.exe"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_xp_unicode_paths_and_neighbors_survive(tmp_path, path, chunk_size):
    paths = [r"C:\first.exe", path, r"C:\last.exe"]
    documents, runner = _read_native(
        tmp_path,
        _winxp_cache([_winxp_entry(path) for path in paths]),
        chunk_size=chunk_size,
    )
    assert [doc["reg2es"]["custom"]["path"] for doc in documents] == paths
    assert runner.successful_records == 3
    assert runner.failed_records == 0


def _bad_xp_entry(kind):
    entry = bytearray(_winxp_entry(r"C:\bad.exe"))
    if kind == "surrogate":
        entry[:4] = b"\x00\xd8\x00\x00"
    else:
        entry[: shimcache.MAX_PATH + 8] = b"A\x00" * ((shimcache.MAX_PATH + 8) // 2)
    return bytes(entry)


@pytest.mark.parametrize("kind", ["surrogate", "unterminated"])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_xp_bad_entry_reports_once_and_recovers_neighbors(
    tmp_path,
    kind,
    chunk_size,
):
    cache = _winxp_cache(
        [
            _winxp_entry(r"C:\first.exe"),
            _bad_xp_entry(kind),
            _winxp_entry(r"C:\last.exe"),
        ]
    )
    documents, runner = _read_native(tmp_path, cache, chunk_size=chunk_size)
    assert [doc["reg2es"]["custom"]["path"] for doc in documents] == [
        r"C:\first.exe",
        *([r"\ud800"] if kind == "surrogate" else []),
        r"C:\last.exe",
    ]
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == (
        "path_decode" if kind == "surrogate" else "shimcache"
    )
    assert runner.errors[0]["value"] == "AppCompatCache"
    if kind == "surrogate":
        assert documents[1]["reg2es"]["custom"]["path_utf16le"] == "00d8"
    else:
        assert "byte 952" in runner.errors[0]["error"]


@pytest.mark.parametrize(
    "cache", [b"", b"?" * 16, struct.pack("<I", shimcache.WINXP_MAGIC32)]
)
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_unknown_or_truncated_cache_honors_error_policy(tmp_path, cache, policy):
    source = _write_hive(tmp_path, cache)
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["shimcache"], error_policy=policy)
    try:
        if policy == "raise":
            with pytest.raises(ValueError):
                list(runner.gen_records())
        else:
            assert list(runner.gen_records()) == []
        assert runner.failed_records == 1
        assert runner.errors[0]["stage"] == "shimcache"
        assert runner.errors[0]["value"] == "AppCompatCache"
    finally:
        runner.close()
    assert source.read_bytes() == before


@pytest.mark.parametrize("format_name", ["win8", "win81", "win10", "creators"])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_modern_frame_failure_does_not_hide_later_entries(
    tmp_path, format_name, policy
):
    cache = _modern_cache(
        format_name,
        [
            _modern_body(format_name, r"C:\first.exe"),
            b"\x00",
            _modern_body(format_name, r"C:\last.exe"),
        ],
    )
    source = _write_hive(tmp_path, cache)
    runner = Reg2es(source, plugin_names=["shimcache"], error_policy=policy)
    try:
        if policy == "raise":
            with pytest.raises(ValueError):
                list(runner.gen_records())
        else:
            documents = [doc for chunk in runner.gen_records() for doc in chunk]
            assert [doc["reg2es"]["custom"]["path"] for doc in documents] == [
                r"C:\first.exe",
                r"C:\last.exe",
            ]
        assert runner.failed_records == 1
        assert runner.errors[0]["stage"] == "shimcache"
    finally:
        runner.close()


@pytest.mark.parametrize("kind", ["xp", "nt5", "nt6", "win10", "creators"])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_genuinely_empty_cache_is_successful(tmp_path, kind, policy):
    if kind == "xp":
        cache = _winxp_cache([])
    elif kind in ("nt5", "nt6"):
        magic, size = (
            (shimcache.CACHE_MAGIC_NT5_2, shimcache.CACHE_HEADER_SIZE_NT5_2)
            if kind == "nt5"
            else (shimcache.CACHE_MAGIC_NT6_1, shimcache.CACHE_HEADER_SIZE_NT6_1)
        )
        cache = struct.pack("<II", magic, 0) + bytes(size - 8)
    else:
        size = (
            shimcache.WIN10_STATS_SIZE
            if kind == "win10"
            else shimcache.WIN10_CREATORS_STATS_SIZE
        )
        cache = struct.pack("<I", size) + bytes(size - 4)
    documents, runner = _read_native(tmp_path, cache, policy=policy)
    assert documents == []
    assert runner.failed_records == 0


@pytest.mark.parametrize("is32bit", [True, False])
def test_native_nt5_sizes_retain_both_dwords_and_distinct_entries(tmp_path, is32bit):
    path = r"C:\same.exe".encode("utf-16le")
    size = shimcache.NT5_2_ENTRY_SIZE32 if is32bit else shimcache.NT5_2_ENTRY_SIZE64
    path_offset = shimcache.CACHE_HEADER_SIZE_NT5_2 + 2 * size
    entries = b"".join(
        struct.pack(
            "<2H5L" if is32bit else "<2H4xQ4L",
            len(path),
            len(path) + 2,
            path_offset,
            FILETIME & 0xFFFFFFFF,
            FILETIME >> 32,
            1024,
            high,
        )
        for high in (1, 2)
    )
    cache = (
        struct.pack("<II", shimcache.CACHE_MAGIC_NT5_2, 2) + entries + path + b"\0\0"
    )
    documents, runner = _read_native(tmp_path, cache)
    assert [doc["reg2es"]["custom"]["file_size_raw"] for doc in documents] == [
        "4294968320",
        "8589935616",
    ]
    assert len(documents) == 2
    assert runner.failed_records == 0


def test_public_api_reports_partial_cache_with_recovered_records(tmp_path):
    source = _write_hive(
        tmp_path,
        _winxp_cache(
            [
                _winxp_entry(r"C:\first.exe"),
                _bad_xp_entry("surrogate"),
                _winxp_entry(r"C:\last.exe"),
            ]
        ),
    )
    before = source.read_bytes()
    with pytest.raises(PartialExtractionError) as raised:
        reg2json(str(source), plugin_names=["shimcache"])
    assert len(raised.value.records) == 3
    assert raised.value.records[1]["reg2es"]["custom"]["path_utf16le"] == "00d8"
    assert len(raised.value.diagnostics) == 1
    assert source.read_bytes() == before


@pytest.mark.parametrize("format_name", ["json", "jsonl"])
def test_cli_finalizes_partial_cache_output_and_returns_failure(
    tmp_path, run_cli, format_name
):
    source = _write_hive(
        tmp_path,
        _winxp_cache(
            [
                _winxp_entry(r"C:\first.exe"),
                _bad_xp_entry("surrogate"),
                _winxp_entry(r"C:\last.exe"),
            ]
        ),
    )
    before = source.read_bytes()
    output = tmp_path / ("out." + format_name)
    result = run_cli(
        "reg2json",
        [
            "--quiet",
            "--plugin",
            "shimcache",
            "--format",
            format_name,
            "-o",
            str(output),
            str(source),
        ],
    )
    assert result.returncode == 1
    assert "1" in result.stderr
    if format_name == "json":
        documents = orjson.loads(output.read_bytes())
    else:
        documents = [orjson.loads(line) for line in output.read_bytes().splitlines()]
    assert [doc["reg2es"]["custom"]["path"] for doc in documents] == [
        r"C:\first.exe",
        r"\ud800",
        r"C:\last.exe",
    ]
    assert documents[1]["reg2es"]["custom"]["path_utf16le"] == "00d8"
    assert source.read_bytes() == before


@pytest.mark.parametrize("format_name", ["win8", "win81", "win10", "creators"])
@pytest.mark.parametrize("policy", ["continue", "raise"])
def test_native_truncated_declared_frame_is_not_silent_success(
    tmp_path, format_name, policy
):
    first = _modern_body(format_name, r"C:\first.exe")
    cache = _modern_cache(format_name, [first])
    tail = bytearray(
        _modern_cache(format_name, [_modern_body(format_name, r"C:\tail.exe")])
    )
    start = len(tail) - (12 + len(_modern_body(format_name, r"C:\tail.exe")))
    frame = tail[start:]
    struct.pack_into("<L", frame, 8, len(frame) - 12 + 100)
    source = _write_hive(tmp_path, cache + frame)
    runner = Reg2es(source, plugin_names=["shimcache"], error_policy=policy)
    try:
        if policy == "raise":
            with pytest.raises(ValueError, match="Truncated entry frame"):
                list(runner.gen_records())
        else:
            documents = [doc for chunk in runner.gen_records() for doc in chunk]
            assert [doc["reg2es"]["custom"]["path"] for doc in documents] == [
                r"C:\first.exe"
            ]
        assert runner.failed_records == 1
        assert "Truncated entry frame" in runner.errors[0]["error"]
    finally:
        runner.close()


@pytest.mark.parametrize("is32bit", [True, False])
def test_native_nt5_flag_format_does_not_become_a_file_size(tmp_path, is32bit):
    path = r"C:\same.exe".encode("utf-16le")
    size = shimcache.NT5_2_ENTRY_SIZE32 if is32bit else shimcache.NT5_2_ENTRY_SIZE64
    path_offset = shimcache.CACHE_HEADER_SIZE_NT5_2 + 2 * size
    entries = b"".join(
        struct.pack(
            "<2H5L" if is32bit else "<2H4xQ4L",
            len(path),
            len(path) + 2,
            path_offset,
            FILETIME & 0xFFFFFFFF,
            FILETIME >> 32,
            flag,
            0x100,
        )
        for flag in (0, shimcache.CSRSS_FLAG)
    )
    cache = (
        struct.pack("<II", shimcache.CACHE_MAGIC_NT5_2, 2) + entries + path + b"\0\0"
    )
    documents, runner = _read_native(tmp_path, cache)
    assert [doc["reg2es"]["custom"]["exec_flag"] for doc in documents] == [
        "False",
        "True",
    ]
    assert all("file_size_raw" not in doc["reg2es"]["custom"] for doc in documents)
    assert runner.failed_records == 0


@pytest.mark.parametrize("format_name", ["nt5", "nt6"])
@pytest.mark.parametrize("is32bit", [True, False])
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_legacy_bad_path_recovers_fixed_table_neighbors(
    tmp_path,
    format_name,
    is32bit,
    chunk_size,
):
    is_nt5 = format_name == "nt5"
    header_size = (
        shimcache.CACHE_HEADER_SIZE_NT5_2
        if is_nt5
        else shimcache.CACHE_HEADER_SIZE_NT6_1
    )
    magic = shimcache.CACHE_MAGIC_NT5_2 if is_nt5 else shimcache.CACHE_MAGIC_NT6_1
    if is_nt5:
        entry_size = (
            shimcache.NT5_2_ENTRY_SIZE32 if is32bit else shimcache.NT5_2_ENTRY_SIZE64
        )
        entry_format = "<2H5L" if is32bit else "<2H4xQ4L"
    else:
        entry_size = (
            shimcache.NT6_1_ENTRY_SIZE32 if is32bit else shimcache.NT6_1_ENTRY_SIZE64
        )
        entry_format = "<2H7L" if is32bit else "<2H4xQ4L2Q"
    paths = [r"C:\first.exe", r"C:\bad.exe", r"C:\last.exe"]
    path_data, entries = bytearray(), bytearray()
    for index, path in enumerate(paths):
        encoded = path.encode("utf-16le")
        pointer = header_size + len(paths) * entry_size + len(path_data)
        if index == 1:
            pointer = 0xFFFFFFFF
        fields = [
            len(encoded),
            len(encoded) + 2,
            pointer,
            FILETIME & 0xFFFFFFFF,
            FILETIME >> 32,
        ]
        fields.extend([1024, 1] if is_nt5 else [shimcache.CSRSS_FLAG, 0, 0, 0])
        entries.extend(struct.pack(entry_format, *fields))
        path_data.extend(encoded + b"\0\0")
    cache = (
        struct.pack("<II", magic, len(paths))
        + bytes(header_size - 8)
        + entries
        + path_data
    )
    documents, runner = _read_native(tmp_path, cache, chunk_size=chunk_size)
    assert [doc["reg2es"]["custom"]["path"] for doc in documents] == [
        paths[0],
        paths[2],
    ]
    assert runner.failed_records == 1
    assert "Truncated ShimCache path" in runner.errors[0]["error"]


@pytest.mark.parametrize("format_name", ["json", "jsonl"])
def test_cli_unknown_cache_returns_failure_without_creating_output(
    tmp_path, run_cli, format_name
):
    source = _write_hive(tmp_path, b"?" * 16)
    original = source.read_bytes()
    output = tmp_path / ("out." + format_name)
    result = run_cli(
        "reg2json",
        [
            "--quiet",
            "--plugin",
            "shimcache",
            "--format",
            format_name,
            "-o",
            str(output),
            str(source),
        ],
    )
    assert result.returncode == 1
    assert "ShimCache" in result.stderr
    assert not output.exists()
    assert source.read_bytes() == original
