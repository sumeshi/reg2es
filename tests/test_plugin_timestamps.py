"""Focused checks for plugin-owned artifact timestamp parsing."""

from datetime import datetime, timezone
import struct

from reg2es.plugins.base import filetime_to_datetime
from reg2es.plugins.office_macros import _office_enabled_time
from reg2es.plugins.tasks import _dynamic_filetime

FILETIME_2024 = 133485408001234560
FILETIME = FILETIME_2024


def test_filetime_helper_rejects_zero_and_out_of_range_values():
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None
    assert filetime_to_datetime(b"short") is None


def test_office_trustrecord_enabled_time_uses_known_24_byte_layout():
    raw = bytearray(24)
    struct.pack_into("<I", raw, 16, 0x01A3D3C0)
    parsed = _office_enabled_time(bytes(raw))
    assert parsed is not None
    assert parsed[1] == 0x01A3D3C0
    assert parsed[0] > 0
    assert _office_enabled_time(bytes(raw[:20])) is None


def test_task_dynamic_info_selects_last_start_and_rejects_unknown_length():
    raw = bytearray(28)
    struct.pack_into("<Q", raw, 4, FILETIME - 10_000_000)
    struct.pack_into("<Q", raw, 12, FILETIME)
    parsed = _dynamic_filetime(bytes(raw), 12)
    assert parsed is not None
    assert parsed[1] == FILETIME
    assert parsed[0].tzinfo == timezone.utc
    assert _dynamic_filetime(bytes(24), 12) is None


def test_filetime_datetime_is_truncated_to_datetime_precision_with_raw_value():
    parsed = filetime_to_datetime(FILETIME + 7)
    assert parsed is not None
    assert parsed[0] == datetime(2024, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)
    assert parsed[1] == FILETIME + 7


def test_task_dynamic_info_rejects_overflow_without_raising():
    # A corrupt QWORD must fall back, not abort the whole plugin run.
    raw = bytearray(28)
    struct.pack_into("<Q", raw, 12, 0x7FFFFFFFFFFFFFFF)
    assert _dynamic_filetime(bytes(raw), 12) is None
    struct.pack_into("<Q", raw, 12, 0)
    assert _dynamic_filetime(bytes(raw), 12) is None


def test_office_enabled_time_matches_minutes_since_unix_epoch():
    # Published dissect.test vector: 0x01B3DEAB -> 2024-04-23 22:03:00 UTC.
    raw = bytearray(24)
    struct.pack_into("<I", raw, 16, 0x01B3DEAB)
    parsed = _office_enabled_time(bytes(raw))
    assert parsed is not None
    assert parsed[0] == 0x01B3DEAB * 60
    assert (
        datetime.fromtimestamp(parsed[0], tz=timezone.utc).isoformat()
        == "2024-04-23T22:03:00+00:00"
    )
    struct.pack_into("<I", raw, 16, 0)
    assert _office_enabled_time(bytes(raw)) is None
