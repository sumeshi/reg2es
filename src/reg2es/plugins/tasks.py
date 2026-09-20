# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

import struct

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime


def _dynamic_filetime(raw, offset):
    """Decode a DynamicInfo FILETIME at a documented offset."""
    if (
        not isinstance(raw, (bytes, bytearray))
        or len(raw) not in (28, 36)
        or len(raw) < offset + 8
    ):
        return None
    value = struct.unpack_from("<Q", raw, offset)[0]
    # Reuse the shared converter so sentinel and out-of-range values are
    # rejected without raising and aborting the whole plugin run.
    return filetime_to_datetime(value)


class Plugin(BasePlugin):
    """Retrieves all Scheduled Tasks in the registry cache"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        k = self.open_key(r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache")
        if not k:
            return

        version_k = self.open_key(r"Microsoft\Windows NT\CurrentVersion")
        if not version_k:
            return

        current_build = int(version_k.value("CurrentBuild").value())
        task_prefix = "%WINDIR%"
        if current_build >= 6002:
            # Since Windows Vista (Task Scheduler 2.0), tasks are stored in %System32%
            task_prefix = "%System32%"

        boot_guids = []
        logon_guids = []
        maintenance_guids = []
        plain_guids = []

        for t in ["Boot", "Logon", "Maintenance", "Plain"]:
            if t not in [x.name() for x in k.subkeys()]:
                continue
            for guid in k.subkey(t).subkeys():
                g = guid.name()
                if t == "Boot":
                    boot_guids.append(g)
                elif t == "Logon":
                    logon_guids.append(g)
                elif t == "Maintenance":
                    maintenance_guids.append(g)
                elif t == "Plain":
                    plain_guids.append(g)

        for task in k.subkey("Tasks").subkeys():
            guid = task.name()
            runtype = "N/A"
            if guid in boot_guids:
                runtype = "Boot"
            elif guid in logon_guids:
                runtype = "Logon"
            elif guid in maintenance_guids:
                runtype = "Maintenance"
            elif guid in plain_guids:
                runtype = "Plain"

            r = PluginResult(key=task)
            task_values = [x.name() for x in task.values()]
            r.custom = {
                "RunType": runtype,
                "Path": f"{task_prefix}\\Tasks{task.value('Path').value()}",
                "Actions": (
                    RegistryAction.from_binary(task.value("Actions").value())
                    if "Actions" in task_values
                    else RegistryAction(None, None)
                ),
                "Source": (
                    task.value("Source").value() if "Source" in task_values else None
                ),
                "Author": (
                    task.value("Author").value() if "Author" in task_values else None
                ),
                "Description": (
                    task.value("Description").value()
                    if "Description" in task_values
                    else None
                ),
            }
            dynamic = None
            if "DynamicInfo" in task_values:
                try:
                    dynamic = task.value("DynamicInfo").value()
                except Registry.RegistryValueNotFoundException:
                    dynamic = None
            # TaskCache DynamicInfo is documented as 28/36 bytes: creation at
            # offset 4, last start at 12, and last stop at 28 for the 36-byte
            # form.  Last start represents the latest execution when present;
            # creation is the meaningful fallback for a never-run task.
            start = _dynamic_filetime(dynamic, 12)
            created = _dynamic_filetime(dynamic, 4)
            stopped = (
                _dynamic_filetime(dynamic, 28)
                if isinstance(dynamic, (bytes, bytearray)) and len(dynamic) == 36
                else None
            )
            r.custom["DynamicInfo"] = {
                "raw": dynamic,
                "length": (
                    len(dynamic) if isinstance(dynamic, (bytes, bytearray)) else None
                ),
                "last_start": start[1] if start else None,
                "created": created[1] if created else None,
                "last_stop": stopped[1] if stopped else None,
            }
            if start:
                r.set_event_time(
                    start[0],
                    source="TaskCache.DynamicInfo.last_start",
                    meaning="scheduled_task_last_run",
                    precision="microseconds",
                    raw=start[1],
                )
            elif created:
                r.set_event_time(
                    created[0],
                    source="TaskCache.DynamicInfo.created",
                    meaning="scheduled_task_created",
                    precision="microseconds",
                    raw=created[1],
                )
            elif dynamic is None:
                r.mark_timestamp_fallback("taskcache_dynamicinfo_missing")
            else:
                r.mark_timestamp_fallback("taskcache_dynamicinfo_invalid_filetime")
                self.warning(
                    f"plugin=tasks hive={self.hive_name} path={self.hive_path} "
                    f"invalid DynamicInfo for {task.name()}"
                )
            yield r


class RegistryAction(object):
    def __init__(self, runas, cmd, action_id=None, working_directory=None):
        self.runas = runas
        self.cmd = cmd
        if action_id:
            self.action_id = action_id
        if working_directory:
            self.working_directory = working_directory

    def __str__(self):
        return f"RegistryAction<runas={self.runas}, cmd={self.cmd}>"

    @staticmethod
    def _read_utf16_field(binary, offset):
        """Read a byte-length-prefixed UTF-16LE field."""
        if offset + 4 > len(binary):
            raise ValueError("truncated task action field length")
        field_len = int.from_bytes(binary[offset : offset + 4], byteorder="little")
        offset += 4
        field_end = offset + field_len
        if field_len % 2 or field_end > len(binary):
            raise ValueError("invalid task action UTF-16 field length")
        return binary[offset:field_end].decode("utf-16-le"), field_end

    @staticmethod
    def from_binary(binary):
        # First two bytes seem to be some kind of version header
        # - 3: enriched information with user + action
        # - 1: base information with action only
        # whichever the version somewhere later in the structure the following two-byte pattern
        # appears:
        # - 0x66 0x66 (in ASCII "ff"): task runs an executable
        # - 0x77 0x77 (in ASCII "ww"): task performs some other action
        struct_version = int.from_bytes(binary[0:2], byteorder="little")

        if struct_version == 1:
            # struct:
            # - 2 bytes: little-endian version header
            # - 2 bytes: action flag ("ff" or "ww")
            action_type = binary[2:4].decode("ascii")
            if action_type == "ff":
                # struct for "ff" action flag:
                # - 4 bytes: apparently always 0
                # - 4 bytes: unknown; looks like a little-endian int
                # - n bytes: utf-16-le string
                # - 4 bytes: zero padding
                cmd = binary[12:-4].decode("utf-16-le")
                return RegistryAction("", cmd)
            # if action_type == "ww": # currently not parsed

        if struct_version == 3:
            name_len = int.from_bytes(binary[2:6], byteorder="little")
            name = binary[6 : 6 + name_len].decode("utf-16-le")

            offset = 6 + name_len
            action_type = binary[offset : offset + 2].decode("ascii")
            cmd = None
            offset += 2

            if action_type == "ff":
                action_id, offset = RegistryAction._read_utf16_field(binary, offset)
                cmd, offset = RegistryAction._read_utf16_field(binary, offset)
                args, offset = RegistryAction._read_utf16_field(binary, offset)
                working_directory, offset = RegistryAction._read_utf16_field(
                    binary, offset
                )
                if args:
                    cmd += " " + args
                return RegistryAction(name, cmd, action_id, working_directory)

            return RegistryAction(name, cmd)

        return RegistryAction("REGRIPPY_UNSUPPORTED", "REGRIPPY_UNSUPPORTED")
