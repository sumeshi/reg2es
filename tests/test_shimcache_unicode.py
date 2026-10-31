"""Invalid UTF-16 paths retain exact bytes through native hive extraction."""

import struct

import orjson
import pytest

from reg2es import PartialExtractionError, reg2json
from reg2es.models.ElasticsearchUtils import ElasticsearchUtils
from reg2es.models.Reg2es import Reg2es
from reg2es.plugins import shimcache
from tests.test_shimcache_entries import FILETIME, _winxp_cache, _winxp_entry
from tests.test_shimcache_recovery import _modern_cache, _read_native, _write_hive

FORMATS = [
    "xp",
    "nt5-32",
    "nt5-64",
    "nt6-32",
    "nt6-64",
    "win8",
    "win81",
    "win10",
    "creators",
]
PREFIX = r"C:\bad".encode("utf-16le")
SUFFIX = ".exe".encode("utf-16le")
BAD_PATHS = [PREFIX + struct.pack("<H", unit) + SUFFIX for unit in (0xD800, 0xD801)]


def cache_with_paths(format_name, raw_paths):
    if format_name == "xp":
        entries = []
        for raw in raw_paths:
            entry = bytearray(_winxp_entry(""))
            entry[: len(raw) + 2] = raw + b"\0\0"
            entries.append(bytes(entry))
        return _winxp_cache(entries)
    if format_name.startswith(("nt5", "nt6")):
        nt5 = format_name.startswith("nt5")
        is32bit = format_name.endswith("32")
        header = (
            shimcache.CACHE_HEADER_SIZE_NT5_2
            if nt5
            else shimcache.CACHE_HEADER_SIZE_NT6_1
        )
        magic = shimcache.CACHE_MAGIC_NT5_2 if nt5 else shimcache.CACHE_MAGIC_NT6_1
        if nt5:
            size = (
                shimcache.NT5_2_ENTRY_SIZE32
                if is32bit
                else shimcache.NT5_2_ENTRY_SIZE64
            )
            entry_format = "<2H5L" if is32bit else "<2H4xQ4L"
        else:
            size = (
                shimcache.NT6_1_ENTRY_SIZE32
                if is32bit
                else shimcache.NT6_1_ENTRY_SIZE64
            )
            entry_format = "<2H7L" if is32bit else "<2H4xQ4L2Q"
        entries, strings = bytearray(), bytearray()
        for raw in raw_paths:
            fields = [
                len(raw),
                len(raw) + 2,
                header + len(raw_paths) * size + len(strings),
                FILETIME & 0xFFFFFFFF,
                FILETIME >> 32,
            ]
            fields.extend([1024, 1] if nt5 else [shimcache.CSRSS_FLAG, 0, 0, 0])
            entries.extend(struct.pack(entry_format, *fields))
            strings.extend(raw + b"\0\0")
        return (
            struct.pack("<II", magic, len(raw_paths))
            + bytes(header - 8)
            + entries
            + strings
        )
    bodies = []
    for raw in raw_paths:
        body = struct.pack("<H", len(raw)) + raw
        body += (
            struct.pack("<HLLQL", 0, 0, 0, FILETIME, 0)
            if format_name in ("win8", "win81")
            else struct.pack("<Q", FILETIME)
        )
        bodies.append(body)
    return _modern_cache(format_name, bodies)


@pytest.mark.parametrize("format_name", FORMATS)
@pytest.mark.parametrize("chunk_size", [1, 500])
def test_native_distinct_invalid_paths_keep_raw_bytes_ids_and_neighbors(
    tmp_path, format_name, chunk_size
):
    paths = [
        r"C:\first.exe".encode("utf-16le"),
        *BAD_PATHS,
        r"C:\last.exe".encode("utf-16le"),
    ]
    cache = cache_with_paths(format_name, paths)
    documents, runner = _read_native(tmp_path, cache, chunk_size=chunk_size)

    assert len(documents) == runner.successful_records == 4
    custom = [document["reg2es"]["custom"] for document in documents]
    assert [row["path"] for row in custom] == [
        r"C:\first.exe",
        r"C:\bad\ud800.exe",
        r"C:\bad\ud801.exe",
        r"C:\last.exe",
    ]
    assert [row["path_utf16le"] for row in custom[1:3]] == [
        raw.hex() for raw in BAD_PATHS
    ]
    assert all("path_utf16le" not in custom[index] for index in (0, 3))
    assert runner.failed_records == 2
    assert all(diagnostic["stage"] == "path_decode" for diagnostic in runner.errors)
    assert all(diagnostic["value"] == "AppCompatCache" for diagnostic in runner.errors)
    assert all(
        diagnostic["error"].startswith("UnicodeDecodeError:")
        for diagnostic in runner.errors
    )
    transport = object.__new__(ElasticsearchUtils)
    assert len({transport.calc_hash(document) for document in documents}) == 4
    assert orjson.loads(orjson.dumps(documents)) == documents
    # Parser results must distinguish the original bytes before legacy dedup.
    entries = shimcache.read_cache(cache)
    assert [entry.path_raw for entry in entries] == [None, *BAD_PATHS, None]


@pytest.mark.parametrize("format_name", FORMATS)
def test_native_strict_path_decode_reports_once(tmp_path, format_name):
    source = _write_hive(tmp_path, cache_with_paths(format_name, BAD_PATHS))
    before = source.read_bytes()
    runner = Reg2es(source, plugin_names=["shimcache"], error_policy="raise")
    with pytest.raises(UnicodeDecodeError):
        list(runner.gen_records())
    assert runner.failed_records == 1
    assert runner.errors[0]["stage"] == "path_decode"
    assert source.read_bytes() == before


@pytest.mark.parametrize("format_name", FORMATS)
def test_native_escaped_display_does_not_collide_with_literal_path(
    tmp_path, format_name
):
    # The readable path literally contains the escape text; only the first
    # document needs original bytes to distinguish it from that valid path.
    literal = r"C:\bad\ud800.exe".encode("utf-16le")
    documents, runner = _read_native(
        tmp_path, cache_with_paths(format_name, [BAD_PATHS[0], literal])
    )
    assert (
        documents[0]["reg2es"]["custom"]["path"]
        == documents[1]["reg2es"]["custom"]["path"]
    )
    assert "path_utf16le" not in documents[1]["reg2es"]["custom"]
    transport = object.__new__(ElasticsearchUtils)
    assert transport.calc_hash(documents[0]) != transport.calc_hash(documents[1])
    assert runner.failed_records == 1


@pytest.mark.parametrize("raw", [b"a", b"a\0b", b"\0\xdc"])
def test_native_odd_length_or_low_surrogate_preserves_complete_path(tmp_path, raw):
    documents, runner = _read_native(tmp_path, cache_with_paths("win10", [raw]))
    assert documents[0]["reg2es"]["custom"]["path_utf16le"] == raw.hex()
    assert runner.failed_records == 1
    orjson.dumps(documents)


@pytest.mark.parametrize("format_name", ["win8", "win10"])
def test_public_api_exposes_recovered_paths_and_diagnostics(tmp_path, format_name):
    source = _write_hive(tmp_path, cache_with_paths(format_name, BAD_PATHS))
    before = source.read_bytes()
    with pytest.raises(PartialExtractionError) as caught:
        reg2json(source, plugin_names=["shimcache"])
    assert len(caught.value.records) == len(caught.value.diagnostics) == 2
    assert [
        doc["reg2es"]["custom"]["path_utf16le"] for doc in caught.value.records
    ] == [raw.hex() for raw in BAD_PATHS]
    assert all(item["stage"] == "path_decode" for item in caught.value.diagnostics)
    assert source.read_bytes() == before


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_native_cli_finalizes_distinct_recovered_paths_with_failure_exit(
    tmp_path, run_cli, output_format
):
    source = _write_hive(tmp_path, cache_with_paths("win10", BAD_PATHS))
    before = source.read_bytes()
    output = tmp_path / ("records." + output_format)
    result = run_cli(
        "reg2json",
        [
            str(source),
            "--plugin",
            "shimcache",
            "--quiet",
            "--format",
            output_format,
            "-o",
            str(output),
        ],
    )
    assert result.returncode == 1
    assert "path_decode" in result.stderr
    rows = (
        orjson.loads(output.read_bytes())
        if output_format == "json"
        else [orjson.loads(line) for line in output.read_bytes().splitlines()]
    )
    assert [row["reg2es"]["custom"]["path_utf16le"] for row in rows] == [
        raw.hex() for raw in BAD_PATHS
    ]
    assert source.read_bytes() == before
