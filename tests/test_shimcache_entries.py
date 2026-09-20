"""Regression checks for ShimCache entry parsing (XP branch and dedup)."""

import struct
import logging

import orjson
import pytest
from Registry.Registry import RegBin

from reg2es.plugins import shimcache
from reg2es.models.Reg2es import plugin_result_to_document
from tests.regrippy.reg_mock import RegistryKeyMock, RegistryMock, RegistryValueMock

FILETIME = 133485408001234560  # 2024-01-01 00:00:00.123456 UTC
ENTRY_DATA = shimcache.MAX_PATH + 8


def _winxp_entry(path, filetime=FILETIME, *, file_size=1024, cache_update=FILETIME):
    entry = bytearray(shimcache.WINXP_ENTRY_SIZE32)
    encoded = path.encode("utf-16le") + b"\x00\x00"
    entry[0 : len(encoded)] = encoded
    struct.pack_into("<2L", entry, ENTRY_DATA, filetime & 0xFFFFFFFF, filetime >> 32)
    struct.pack_into("<Q", entry, ENTRY_DATA + 8, file_size)
    struct.pack_into("<Q", entry, ENTRY_DATA + 16, cache_update)
    return bytes(entry)


def _winxp_cache(entries):
    header = bytearray(shimcache.WINXP_HEADER_SIZE32)
    struct.pack_into("<L", header, 0, shimcache.WINXP_MAGIC32)
    struct.pack_into("<L", header, 8, len(entries))
    return bytes(header) + b"".join(entries)


def test_winxp_entries_are_parsed_and_expose_file_mtime():
    cache = _winxp_cache([_winxp_entry(r"C:\Windows\evil.exe")])
    entries = shimcache.read_cache(cache)
    assert entries is not None
    assert len(entries) == 1
    assert entries[0].path == r"C:\Windows\evil.exe"
    assert entries[0].file_time is not None
    assert entries[0].raw_filetime == FILETIME


def test_winxp_identical_entries_are_deduplicated():
    cache = _winxp_cache(
        [
            _winxp_entry(r"C:\same.exe", FILETIME),
            _winxp_entry(r"C:\same.exe", FILETIME),
        ]
    )
    entries = shimcache.read_cache(cache)
    assert entries is not None
    assert len(entries) == 1


@pytest.mark.parametrize("delta", [1, 1_000_000])
def test_winxp_distinct_filetimes_in_the_same_second_are_preserved(delta):
    cache = _winxp_cache(
        [_winxp_entry(r"C:\same.exe"), _winxp_entry(r"C:\same.exe", FILETIME + delta)]
    )
    entries = shimcache.read_cache(cache)
    assert len(entries) == 2
    assert [entry.raw_filetime for entry in entries] == [FILETIME, FILETIME + delta]


@pytest.mark.parametrize(
    "difference", [{"file_size": 2048}, {"cache_update": FILETIME + 1}]
)
def test_winxp_other_evidence_fields_participate_in_identity(difference):
    entries = shimcache.read_cache(
        _winxp_cache(
            [
                _winxp_entry(r"C:\same.exe"),
                _winxp_entry(r"C:\same.exe", **difference),
            ]
        )
    )
    assert len(entries) == 2


@pytest.mark.parametrize("delta", [0, 1, 1_000_000])
def test_win10_preserves_every_physical_entry(delta):
    path = r"C:\same.exe".encode("utf-16le")
    cache = bytearray(shimcache.WIN10_STATS_SIZE)
    for filetime in (FILETIME, FILETIME + delta):
        body = struct.pack("<H", len(path)) + path + struct.pack("<Q", filetime)
        cache.extend(struct.pack("<4sLL", b"10ts", 0, len(body)) + body)
    entries = shimcache.read_win10_entries(bytes(cache), b"10ts")
    assert len(entries) == 2
    assert [entry.raw_filetime for entry in entries] == [FILETIME, FILETIME + delta]


def test_invalid_unsigned_times_remain_serializable_raw_text():
    maximum = 0xFFFFFFFFFFFFFFFF
    cache = _winxp_cache(
        [
            _winxp_entry(r"C:\example.exe", maximum, cache_update=maximum),
        ]
    )
    key = RegistryKeyMock.build(r"ControlSet001\Control\Session Manager\AppCompatCache")
    key.add_value(RegistryValueMock("AppCompatCache", cache, RegBin))
    reg = RegistryMock("SYSTEM", "system", key.root())
    reg.set_ccs(1)
    results = list(
        shimcache.Plugin(reg, logging.getLogger(__name__), "SYSTEM", "-").run()
    )
    assert len(results) == 1
    doc = plugin_result_to_document(results[0], "shimcache", "SYSTEM", "-")
    assert doc["reg2es"]["timestamp"]["source"] == "key.last_write"
    custom = doc["reg2es"]["custom"]
    assert custom["file_mtime_raw"] == custom["cache_update_raw"] == str(maximum)
    assert custom["file_size_raw"] == "1024"
    orjson.dumps(doc)
