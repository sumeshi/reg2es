# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

# Plugin written by Tim Taylor, timtaylor3@yahoo.com
import struct

from Registry.RegistryParse import parse_windows_timestamp

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Return the last shutdown time"""

    __REGHIVE__ = "SYSTEM"

    def run(self):

        key = self.open_key(self.get_currentcontrolset_path() + r"\Control\Windows")
        if not key:
            return

        for v in key.values():
            if v.name() == "ShutdownTime":
                binary = struct.unpack("<Q", v.value())[0]
                dt = parse_windows_timestamp(binary)
                value = dt.isoformat("T") + "Z"
                res = PluginResult(key=key, value=v)
                res.custom["LastShutdownTime"] = value
                yield res
