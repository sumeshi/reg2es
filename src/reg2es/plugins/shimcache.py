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
        "date path exec_flag file_time raw_filetime file_size cache_update_raw",
        defaults=(None, None),
    )
):
    """One parsed Shim Cache entry.

    ``file_time`` is the target file's last-modification ``datetime`` (or
    ``None``) and ``raw_filetime`` is the original 100-ns FILETIME integer.
    ``exec_flag``/``date`` are the legacy display fields.
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
    )


# Read the Shim Cache format, return a list of last modified dates/paths.
def read_cache(cachebin):

    if len(cachebin) < 16:
        # Data size less than minimum header size.
        return None

    try:
        # Get the format type
        magic = struct.unpack("<L", cachebin[0:4])[0]

        # This is a Windows 2k3/Vista/2k8 Shim Cache format,
        if magic == CACHE_MAGIC_NT5_2:

            # Shim Cache types can come in 32-bit or 64-bit formats. We can
            # determine this because 64-bit entries are serialized with u_int64
            # pointers. This means that in a 64-bit entry, valid UNICODE_STRING
            # sizes are followed by a NULL DWORD. Check for this here.
            test_size = struct.unpack("<H", cachebin[8:10])[0]
            test_max_size = struct.unpack("<H", cachebin[10:12])[0]
            if (
                test_max_size - test_size == 2
                and struct.unpack("<L", cachebin[12:16])[0]
            ) == 0:
                logger.debug("[+] Found 64bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(False)
                return read_nt5_entries(cachebin, entry)

            # Otherwise it's 32-bit data.
            else:
                logger.debug("[+] Found 32bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(True)
                return read_nt5_entries(cachebin, entry)

        # This is a Windows 7/2k8-R2 Shim Cache.
        elif magic == CACHE_MAGIC_NT6_1:
            test_size = struct.unpack(
                "<H", cachebin[CACHE_HEADER_SIZE_NT6_1 : CACHE_HEADER_SIZE_NT6_1 + 2]
            )[0]
            test_max_size = struct.unpack(
                "<H",
                cachebin[CACHE_HEADER_SIZE_NT6_1 + 2 : CACHE_HEADER_SIZE_NT6_1 + 4],
            )[0]

            # Shim Cache types can come in 32-bit or 64-bit formats.
            # We can determine this because 64-bit entries are serialized with
            # u_int64 pointers. This means that in a 64-bit entry, valid
            # UNICODE_STRING sizes are followed by a NULL DWORD. Check for this here.
            if (
                test_max_size - test_size == 2
                and struct.unpack(
                    "<L",
                    cachebin[CACHE_HEADER_SIZE_NT6_1 + 4 : CACHE_HEADER_SIZE_NT6_1 + 8],
                )[0]
            ) == 0:
                logger.debug("[+] Found 64bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(False)
                return read_nt6_entries(cachebin, entry)
            else:
                logger.debug("[+] Found 32bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(True)
                return read_nt6_entries(cachebin, entry)

        # This is WinXP cache data
        elif magic == WINXP_MAGIC32:
            logger.debug("[+] Found 32bit Windows XP Shim Cache data...")
            return read_winxp_entries(cachebin)

        # Check the data set to see if it matches the Windows 8 format.
        elif (
            len(cachebin) > WIN8_STATS_SIZE
            and cachebin[WIN8_STATS_SIZE : WIN8_STATS_SIZE + 4] == WIN8_MAGIC
        ):
            logger.debug("[+] Found Windows 8/2k12 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN8_MAGIC)

        # Windows 8.1 will use a different magic dword, check for it
        elif (
            len(cachebin) > WIN8_STATS_SIZE
            and cachebin[WIN8_STATS_SIZE : WIN8_STATS_SIZE + 4] == WIN81_MAGIC
        ):
            logger.debug("[+] Found Windows 8.1 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN81_MAGIC)

        # Windows 10 will use a different magic dword, check for it
        elif (
            len(cachebin) > WIN10_STATS_SIZE
            and cachebin[WIN10_STATS_SIZE : WIN10_STATS_SIZE + 4] == WIN10_MAGIC
        ):
            logger.debug("[+] Found Windows 10 Apphelp Cache data...")
            return read_win10_entries(cachebin, WIN10_MAGIC)

        # Windows 10 Creators Update will use a different STATS_SIZE, account for it
        elif (
            len(cachebin) > WIN10_CREATORS_STATS_SIZE
            and cachebin[WIN10_CREATORS_STATS_SIZE : WIN10_CREATORS_STATS_SIZE + 4]
            == WIN10_MAGIC
        ):
            logger.debug("[+] Found Windows 10 Creators Update Apphelp Cache data...")
            return read_win10_entries(cachebin, WIN10_MAGIC, creators_update=True)

        else:
            logger.error(
                "[-] Got an unrecognized magic value of 0x%x... bailing" % magic
            )
            return None

    except (RuntimeError, TypeError, NameError) as err:
        logger.error("[-] Error reading Shim Cache data: %s" % err)
        return None


# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic):
    offset = 0
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    cache_data = bin_data[WIN8_STATS_SIZE:]

    data = BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack("<4sLL", header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception(
                "Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0]
            )

        entry_data = BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack("<H", entry_data.read(2))[0]
        if path_len == 0:
            path = "None"
        else:
            path = entry_data.read(path_len).decode("utf-16le", "replace")

        # Check for package data
        package_len = struct.unpack("<H", entry_data.read(2))[0]
        if package_len > 0:
            # Just skip past the package data if present (for now)
            entry_data.seek(package_len, 1)

        # Read the remaining entry data
        flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack(
            "<LLLLL", entry_data.read(20)
        )

        # Check the flag set in CSRSS
        if flags & CSRSS_FLAG:
            exec_flag = "True"
        else:
            exec_flag = "False"

        entry_list.append(
            _make_entry(low_datetime, high_datetime, path, exec_flag=exec_flag),
        )

    return entry_list


# Read Windows 10 Apphelp Cache entry format
def read_win10_entries(bin_data, ver_magic, creators_update=False):

    offset = 0
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    if creators_update:
        cache_data = bin_data[WIN10_CREATORS_STATS_SIZE:]
    else:
        cache_data = bin_data[WIN10_STATS_SIZE:]

    data = BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack("<4sLL", header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception(
                "Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0]
            )

        entry_data = BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack("<H", entry_data.read(2))[0]
        if path_len == 0:
            path = "None"
        else:
            path = entry_data.read(path_len).decode("utf-16le", "replace")

        # Read the remaining entry data
        low_datetime, high_datetime = struct.unpack("<LL", entry_data.read(8))

        # Keep every physical entry, including entries whose time is unknown.
        entry_list.append(_make_entry(low_datetime, high_datetime, path))

    return entry_list


# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry):

    try:
        entry_list = []
        contains_file_size = False
        entry_size = entry.size()

        num_entries = struct.unpack("<L", bin_data[4:8])[0]
        if num_entries == 0:
            return None

        # On Windows Server 2008/Vista, the filesize is swapped out of this
        # structure with two 4-byte flags. Check to see if any of the values in
        # "dwFileSizeLow" are larger than 2-bits. This indicates the entry contained file sizes.
        for offset in range(
            CACHE_HEADER_SIZE_NT5_2,
            (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2,
            entry_size,
        ):

            entry.update(bin_data[offset : offset + entry_size])

            if entry.dwFileSizeLow > 3:
                contains_file_size = True
                break

        # Now grab all the data in the value.
        for offset in range(
            CACHE_HEADER_SIZE_NT5_2,
            (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2,
            entry_size,
        ):

            entry.update(bin_data[offset : offset + entry_size])

            path = bin_data[entry.Offset : entry.Offset + entry.wLength].decode(
                "utf-16le", "replace"
            )

            # Filesize-format entries have no CSRSS flag to report; flag-format
            # entries do.
            exec_flag = "N/A"
            if not contains_file_size:
                exec_flag = "True" if entry.dwFileSizeLow & CSRSS_FLAG else "False"

            _append_entry(
                entry_list,
                _make_entry(
                    entry.dwLowDateTime,
                    entry.dwHighDateTime,
                    path,
                    exec_flag=exec_flag,
                    file_size=entry.dwFileSizeLow if contains_file_size else None,
                ),
            )

        return entry_list

    except (RuntimeError, ValueError, NameError) as err:
        logger.error("[-] Error reading Shim Cache data: %s..." % err)
        return None


# Read the Shim Cache Windows 7/2k8-R2 entry format,
# return a list of last modifed dates/paths.
def read_nt6_entries(bin_data, entry):

    try:
        entry_list = []
        exec_flag = ""
        entry_size = entry.size()
        num_entries = struct.unpack("<L", bin_data[4:8])[0]

        if num_entries == 0:
            return None

        # Walk each entry in the data structure.
        for offset in range(
            CACHE_HEADER_SIZE_NT6_1,
            num_entries * entry_size + CACHE_HEADER_SIZE_NT6_1,
            entry_size,
        ):

            entry.update(bin_data[offset : offset + entry_size])
            path = bin_data[entry.Offset : entry.Offset + entry.wLength].decode(
                "utf-16le", "replace"
            )

            # Test to see if the file may have been executed.
            exec_flag = "True" if entry.FileFlags & CSRSS_FLAG else "False"
            _append_entry(
                entry_list,
                _make_entry(
                    entry.dwLowDateTime,
                    entry.dwHighDateTime,
                    path,
                    exec_flag=exec_flag,
                ),
            )
        return entry_list

    except (RuntimeError, ValueError, NameError) as err:
        logger.error("[-] Error reading Shim Cache data: %s..." % err)
        return None


# Read the WinXP Shim Cache data. Some entries can be missing data but still
# contain useful information, so try to get as much as we can.
def read_winxp_entries(bin_data):

    entry_list = []

    try:

        num_entries = struct.unpack("<L", bin_data[8:12])[0]
        if num_entries == 0:
            return None

        for offset in range(
            WINXP_HEADER_SIZE32,
            (num_entries * WINXP_ENTRY_SIZE32) + WINXP_HEADER_SIZE32,
            WINXP_ENTRY_SIZE32,
        ):

            # No size values are included in these entries, so search for utf-16 terminator.
            path_len = bin_data[offset : offset + (MAX_PATH + 8)].find(b"\x00\x00")

            # if path is corrupt, procede to next entry.
            if path_len == 0:
                continue
            path = bin_data[offset : offset + path_len + 1].decode("utf-16le")

            entry_data = offset + (MAX_PATH + 8)

            # Get last mod time.
            last_mod_time = struct.unpack("<2L", bin_data[entry_data : entry_data + 8])
            file_size = struct.unpack_from("<Q", bin_data, entry_data + 8)[0]
            cache_update_raw = struct.unpack_from("<Q", bin_data, entry_data + 16)[0]

            _append_entry(
                entry_list,
                _make_entry(
                    last_mod_time[0],
                    last_mod_time[1],
                    path,
                    file_size=file_size,
                    cache_update_raw=cache_update_raw,
                ),
            )
        return entry_list

    except (RuntimeError, ValueError, TypeError, NameError) as err:
        logger.error("[-] Error reading Shim Cache data %s" % err)
        return None


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
        read_cache_results = read_cache(key.value("AppCompatCache").value())
        if not read_cache_results:
            return

        for entry in read_cache_results:
            res = PluginResult(key=key, value=None)
            res.custom["date"] = entry.date
            # Raw unsigned QWORDs can exceed Elasticsearch's signed long
            # range, especially sentinels; keep a stable, lossless text type.
            res.custom["file_mtime_raw"] = str(entry.raw_filetime)
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
