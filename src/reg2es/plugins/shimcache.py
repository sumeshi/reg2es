# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
#
# The Shim Cache parser below is derived from ShimCacheParser.py:
# Andrew Davis, andrew.davis@mandiant.com
# Copyright 2012 Mandiant
# Licensed under the Apache License, Version 2.0.
#
# Modifications: regrippy imports were changed to reg2es.plugins and the
# formerly separate ShimCacheParser module was integrated; unused CLI display helpers removed.
# Artifact times retain raw FILETIME precision; Win8/10 preserve every entry.
# Available execution flags are retained in plugin custom data.
# Invalid UTF-16 paths retain their original bytes and report decoding errors.

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime

import logging
import struct
from collections import namedtuple
from io import BytesIO

logging.basicConfig()
logger = logging.getLogger("shimcacheparser")
logger.setLevel("ERROR")

# Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xBADC0FFE
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xBADC0FEE
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xDEADBEEF
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = b"00ts"

# Magic value used by Windows 8.1
WIN81_MAGIC = b"10ts"

# Values used by Windows 10
WIN10_STATS_SIZE = 0x30
WIN10_CREATORS_STATS_SIZE = 0x34
WIN10_MAGIC = b"10ts"
CACHE_HEADER_SIZE_NT6_4 = 0x30
CACHE_MAGIC_NT6_4 = 0x30

bad_entry_data = "N/A"

# Date Formats
DATE_ISO = "%Y-%m-%d %H:%M:%S"
g_timeformat = DATE_ISO


# Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
class CacheEntryNt5(object):
    def __init__(self, is32bit, data=None):

        self.is32bit = is32bit
        if data != None:
            self.update(data)

    def update(self, data):

        if self.is32bit:
            entry = struct.unpack("<2H 3L 2L", data)
        else:
            entry = struct.unpack("<2H 4x Q 2L 2L", data)
        self.wLength = entry[0]
        self.wMaximumLength = entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.dwFileSizeLow = entry[5]
        self.dwFileSizeHigh = entry[6]

    def size(self):

        if self.is32bit:
            return NT5_2_ENTRY_SIZE32
        else:
            return NT5_2_ENTRY_SIZE64


# Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2)
class CacheEntryNt6(object):
    def __init__(self, is32bit, data=None):

        self.is32bit = is32bit
        if data != None:
            self.update(data)

    def update(self, data):

        if self.is32bit:
            entry = struct.unpack("<2H 7L", data)
        else:
            entry = struct.unpack("<2H 4x Q 4L 2Q", data)
        self.wLength = entry[0]
        self.wMaximumLength = entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.FileFlags = entry[5]
        self.Flags = entry[6]
        self.BlobSize = entry[7]
        self.BlobOffset = entry[8]

    def size(self):

        if self.is32bit:
            return NT6_1_ENTRY_SIZE32
        else:
            return NT6_1_ENTRY_SIZE64


# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dwLowDateTime, dwHighDateTime):

    try:
        temp_time = (dwHighDateTime << 32) | dwLowDateTime
        parsed = filetime_to_datetime(temp_time)
        return parsed[0] if parsed else None
    except (TypeError, ValueError, OverflowError):
        return None


class CacheEntry(
    namedtuple(
        "CacheEntry",
        "date path exec_flag file_time raw_filetime file_size cache_update_raw path_raw",
        defaults=(None, None, None),
    )
):
    """One parsed Shim Cache entry.

    ``file_time`` is the target file's last-modification ``datetime`` (or
    ``None``) and ``raw_filetime`` is the original 100-ns FILETIME integer.
    ``exec_flag``/``date`` are the legacy display fields.
    ``path_raw`` is present only when the original UTF-16 path cannot decode.
    """

    __slots__ = ()

    @property
    def dedup_key(self):
        return (
            self.raw_filetime,
            self.path,
            self.exec_flag,
            self.file_size,
            self.cache_update_raw,
            self.path_raw,
        )


def _append_entry(entry_list, entry):
    """Deduplicate legacy entries using the original, unrounded FILETIME."""
    if not any(existing.dedup_key == entry.dedup_key for existing in entry_list):
        entry_list.append(entry)


def _make_entry(
    low_datetime,
    high_datetime,
    path,
    *,
    exec_flag="N/A",
    file_size=None,
    cache_update_raw=None,
    path_raw=None,
):
    """Build a ``CacheEntry`` from a raw FILETIME pair and path."""
    file_time = convert_filetime(low_datetime, high_datetime)
    try:
        date = file_time.strftime(g_timeformat)
    except (AttributeError, ValueError, OverflowError):
        date = bad_entry_data
    raw_filetime = (high_datetime << 32) | low_datetime
    return CacheEntry(
        date=date,
        path=path,
        exec_flag=exec_flag,
        file_time=file_time,
        raw_filetime=raw_filetime,
        file_size=file_size,
        cache_update_raw=cache_update_raw,
        path_raw=path_raw,
    )


_PARSE_ERRORS = (RuntimeError, ValueError, TypeError, NameError, struct.error)


def _report_error(on_error, error, offset=None):
    if offset is not None:
        error = ValueError(f"ShimCache entry at byte {offset}: {error}")
    if on_error is None:
        raise error
    # A strict-policy callback can raise here. Keep it outside parsing try
    # blocks so the same failure is never caught or reported twice.
    on_error(error)


def _read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"Truncated ShimCache data: expected {size} bytes")
    return data


def _decode_path(raw):
    """Escape invalid code units for display and retain the original path."""
    try:
        return raw.decode("utf-16le"), None
    except UnicodeDecodeError:
        try:
            display = raw.decode("utf-16le", "surrogatepass")
        except UnicodeDecodeError:
            # An odd trailing byte has no UTF-16 code unit to display.
            display = raw.decode("utf-16le", "backslashreplace")
        return display.encode("utf8", "backslashreplace").decode("utf8"), raw


def _fixed_entries(bin_data, start, count, size, on_error):
    for index in range(count):
        offset = start + index * size
        if offset + size > len(bin_data):
            _report_error(on_error, ValueError("Truncated entry table"), offset)
            break
        yield offset, bin_data[offset : offset + size]


def _entry_frames(bin_data, start, ver_magic, on_error):
    data = BytesIO(bin_data)
    data.seek(start)
    while data.tell() < len(bin_data):
        offset = data.tell()
        try:
            magic, _crc32, entry_len = struct.unpack("<4sLL", _read_exact(data, 12))
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            break  # A partial frame header has no trustworthy next boundary.
        body = data.read(entry_len)
        if len(body) != entry_len:
            _report_error(on_error, ValueError("Truncated entry frame"), offset)
            break
        if magic != ver_magic:
            _report_error(on_error, ValueError("Invalid version magic tag"), offset)
            continue
        yield offset, BytesIO(body)


# Read the Shim Cache format, returning [] only for a successfully empty cache.
def read_cache(cachebin, on_error=None):
    creators_update = False
    try:
        if len(cachebin) < 4:
            raise ValueError("Truncated ShimCache header")
        magic = struct.unpack_from("<L", cachebin)[0]
        if magic in (CACHE_MAGIC_NT5_2, CACHE_MAGIC_NT6_1):
            header_size = (
                CACHE_HEADER_SIZE_NT5_2
                if magic == CACHE_MAGIC_NT5_2
                else CACHE_HEADER_SIZE_NT6_1
            )
            if len(cachebin) < header_size:
                raise ValueError("Truncated ShimCache header")
            if struct.unpack_from("<L", cachebin, 4)[0] == 0:
                return []
            test_size, test_max_size, padding = struct.unpack_from(
                "<HHL", cachebin, header_size
            )
            is32bit = not (test_max_size - test_size == 2 and padding == 0)
            if magic == CACHE_MAGIC_NT5_2:
                parser, argument = read_nt5_entries, CacheEntryNt5(is32bit)
            else:
                parser, argument = read_nt6_entries, CacheEntryNt6(is32bit)
        elif magic == WINXP_MAGIC32:
            if len(cachebin) < WINXP_HEADER_SIZE32:
                raise ValueError("Truncated Windows XP ShimCache header")
            parser, argument = read_winxp_entries, None
        elif cachebin[WIN8_STATS_SIZE : WIN8_STATS_SIZE + 4] in (
            WIN8_MAGIC,
            WIN81_MAGIC,
        ):
            parser, argument = (
                read_win8_entries,
                cachebin[WIN8_STATS_SIZE : WIN8_STATS_SIZE + 4],
            )
        elif cachebin[WIN10_STATS_SIZE : WIN10_STATS_SIZE + 4] == WIN10_MAGIC:
            parser, argument = read_win10_entries, WIN10_MAGIC
        elif (
            cachebin[WIN10_CREATORS_STATS_SIZE : WIN10_CREATORS_STATS_SIZE + 4]
            == WIN10_MAGIC
        ):
            parser, argument = read_win10_entries, WIN10_MAGIC
            creators_update = True
        elif (
            magic in (WIN10_STATS_SIZE, WIN10_CREATORS_STATS_SIZE)
            and len(cachebin) == magic
        ):
            return []
        else:
            raise ValueError(f"Unrecognized ShimCache magic 0x{magic:x}")
    except _PARSE_ERRORS as error:
        _report_error(on_error, error)
        return []
    if argument is None:
        return parser(cachebin, on_error=on_error)
    if creators_update:
        return parser(cachebin, argument, creators_update=True, on_error=on_error)
    return parser(cachebin, argument, on_error=on_error)


# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic, on_error=None):
    entry_list = []
    for offset, entry_data in _entry_frames(
        bin_data, WIN8_STATS_SIZE, ver_magic, on_error
    ):
        try:
            path_len = struct.unpack("<H", _read_exact(entry_data, 2))[0]
            path, path_raw = (
                _decode_path(_read_exact(entry_data, path_len))
                if path_len
                else ("None", None)
            )
            package_len = struct.unpack("<H", _read_exact(entry_data, 2))[0]
            _read_exact(entry_data, package_len)
            flags, _unk1, low_datetime, high_datetime, _unk2 = struct.unpack(
                "<LLLLL", _read_exact(entry_data, 20)
            )
            entry = _make_entry(
                low_datetime,
                high_datetime,
                path,
                exec_flag="True" if flags & CSRSS_FLAG else "False",
                path_raw=path_raw,
            )
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            continue
        entry_list.append(entry)
    return entry_list


# Read Windows 10 Apphelp Cache entry format.
def read_win10_entries(bin_data, ver_magic, creators_update=False, on_error=None):
    start = WIN10_CREATORS_STATS_SIZE if creators_update else WIN10_STATS_SIZE
    entry_list = []
    for offset, entry_data in _entry_frames(bin_data, start, ver_magic, on_error):
        try:
            path_len = struct.unpack("<H", _read_exact(entry_data, 2))[0]
            path, path_raw = (
                _decode_path(_read_exact(entry_data, path_len))
                if path_len
                else ("None", None)
            )
            low_datetime, high_datetime = struct.unpack(
                "<LL", _read_exact(entry_data, 8)
            )
            entry = _make_entry(low_datetime, high_datetime, path, path_raw=path_raw)
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            continue
        # Keep every physical entry, including entries whose time is unknown.
        entry_list.append(entry)
    return entry_list


# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry, on_error=None):
    entry_list = []
    entry_size = entry.size()
    try:
        num_entries = struct.unpack_from("<L", bin_data, 4)[0]
    except _PARSE_ERRORS as error:
        _report_error(on_error, error)
        return entry_list
    # Vista/Server 2008 replace the two size DWORDs with flags. Preserve the
    # existing distinction, based on complete entries only.
    available = max(0, (len(bin_data) - CACHE_HEADER_SIZE_NT5_2) // entry_size)
    contains_file_size = any(
        struct.unpack_from("<L", bin_data, offset + entry_size - 8)[0] > 3
        for offset in range(
            CACHE_HEADER_SIZE_NT5_2,
            CACHE_HEADER_SIZE_NT5_2 + min(num_entries, available) * entry_size,
            entry_size,
        )
    )
    for offset, raw_entry in _fixed_entries(
        bin_data, CACHE_HEADER_SIZE_NT5_2, num_entries, entry_size, on_error
    ):
        try:
            entry.update(raw_entry)
            path, path_raw = _read_legacy_path(bin_data, entry)
            exec_flag = (
                "N/A"
                if contains_file_size
                else ("True" if entry.dwFileSizeLow & CSRSS_FLAG else "False")
            )
            parsed = _make_entry(
                entry.dwLowDateTime,
                entry.dwHighDateTime,
                path,
                exec_flag=exec_flag,
                file_size=(
                    ((entry.dwFileSizeHigh << 32) | entry.dwFileSizeLow)
                    if contains_file_size
                    else None
                ),
                path_raw=path_raw,
            )
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            continue
        _append_entry(entry_list, parsed)
    return entry_list


def _read_legacy_path(bin_data, entry):
    end = entry.Offset + entry.wLength
    if end > len(bin_data):
        raise ValueError("Truncated ShimCache path")
    return _decode_path(bin_data[entry.Offset : end])


# Read the Shim Cache Windows 7/2k8-R2 entry format.
def read_nt6_entries(bin_data, entry, on_error=None):
    entry_list = []
    try:
        num_entries = struct.unpack_from("<L", bin_data, 4)[0]
    except _PARSE_ERRORS as error:
        _report_error(on_error, error)
        return entry_list
    for offset, raw_entry in _fixed_entries(
        bin_data, CACHE_HEADER_SIZE_NT6_1, num_entries, entry.size(), on_error
    ):
        try:
            entry.update(raw_entry)
            path, path_raw = _read_legacy_path(bin_data, entry)
            parsed = _make_entry(
                entry.dwLowDateTime,
                entry.dwHighDateTime,
                path,
                exec_flag="True" if entry.FileFlags & CSRSS_FLAG else "False",
                path_raw=path_raw,
            )
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            continue
        _append_entry(entry_list, parsed)
    return entry_list


# Fixed-size Windows XP entries let us recover after one unreadable path.
def read_winxp_entries(bin_data, on_error=None):
    entry_list = []
    try:
        num_entries = struct.unpack_from("<L", bin_data, 8)[0]
    except _PARSE_ERRORS as error:
        _report_error(on_error, error)
        return entry_list
    for offset, raw_entry in _fixed_entries(
        bin_data, WINXP_HEADER_SIZE32, num_entries, WINXP_ENTRY_SIZE32, on_error
    ):
        try:
            path_data = raw_entry[: MAX_PATH + 8]
            terminator = next(
                (
                    index
                    for index in range(0, len(path_data), 2)
                    if path_data[index : index + 2] == b"\x00\x00"
                ),
                None,
            )
            if terminator is None:
                raise ValueError("Unterminated Windows XP ShimCache path")
            if terminator == 0:
                continue  # An unused slot has no path or entry to emit.
            path, path_raw = _decode_path(path_data[:terminator])
            low_datetime, high_datetime, file_size, cache_update_raw = (
                struct.unpack_from("<2LQQ", raw_entry, MAX_PATH + 8)
            )
            parsed = _make_entry(
                low_datetime,
                high_datetime,
                path,
                file_size=file_size,
                cache_update_raw=cache_update_raw,
                path_raw=path_raw,
            )
        except _PARSE_ERRORS as error:
            _report_error(on_error, error, offset)
            continue
        _append_entry(entry_list, parsed)
    return entry_list


class Plugin(BasePlugin):
    """Parse shim cache entries describing cached target files."""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key(
            self.get_currentcontrolset_path()
            + r"\Control\Session Manager\AppCompatCache"
        ) or self.open_key(
            self.get_currentcontrolset_path()
            + r"\Control\Session Manager\AppCompatibility"
        )

        if not key:
            return
        value = key.value("AppCompatCache")

        def on_error(error):
            self.record_error(key.path(), value.name(), error, stage="shimcache")

        read_cache_results = read_cache(value.value(), on_error=on_error)
        if not read_cache_results:
            return

        for entry in read_cache_results:
            if entry.path_raw is not None:
                try:
                    entry.path_raw.decode("utf-16le")
                except UnicodeDecodeError as error:
                    self.record_error(
                        key.path(), value.name(), error, stage="path_decode"
                    )
            res = PluginResult(key=key, value=None)
            res.custom["date"] = entry.date
            if entry.exec_flag in ("True", "False"):
                res.custom["exec_flag"] = entry.exec_flag
            # Raw unsigned QWORDs can exceed Elasticsearch's signed long
            # range, especially sentinels; keep a stable, lossless text type.
            res.custom["file_mtime_raw"] = str(entry.raw_filetime)
            if entry.path_raw is not None:
                res.custom["path_utf16le"] = entry.path_raw.hex()
            if entry.file_size is not None:
                res.custom["file_size_raw"] = str(entry.file_size)
            if entry.cache_update_raw is not None:
                res.custom["cache_update_raw"] = str(entry.cache_update_raw)
            if entry.file_time is not None:
                res.set_event_time(
                    entry.file_time,
                    source="ShimCache.file_mtime",
                    meaning="target_file_modified",
                    precision="microseconds",
                    raw=entry.raw_filetime,
                )
            else:
                res.mark_timestamp_fallback("invalid_or_missing_shimcache_file_time")
            if isinstance(entry.path, bytes):
                res.custom["path"] = entry.path.decode("utf8")
            else:
                res.custom["path"] = entry.path
            yield res
