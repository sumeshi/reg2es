# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

# Plugin written by Tim Taylor, timtaylor3@yahoo.com
from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime


class Plugin(BasePlugin):
    """Return the last shutdown time"""

    __REGHIVE__ = "SYSTEM"

    def run(self):

        key = self.open_key(self.get_currentcontrolset_path() + r"\Control\Windows")
        if not key:
            return

        for v in key.values():
            if v.name() == "ShutdownTime":
                res = PluginResult(key=key, value=v)
                try:
                    parsed = filetime_to_datetime(v.value())
                    if parsed is None:
                        raise ValueError("ShutdownTime is malformed or sentinel")
                    dt_utc, binary = parsed
                    value = dt_utc.isoformat("T").replace("+00:00", "Z")
                    res.custom["LastShutdownTime"] = value
                    res.set_event_time(
                        dt_utc,
                        source="ShutdownTime",
                        meaning="shutdown",
                        precision="microseconds",
                        raw=binary,
                    )
                except (TypeError, ValueError, OverflowError) as exc:
                    res.custom["LastShutdownTime"] = "N/A"
                    res.mark_timestamp_fallback("invalid_shutdowntime_filetime")
                    self.warning(
                        f"plugin=lastshutdown hive={self.hive_name} path={self.hive_path} "
                        f"invalid ShutdownTime: {exc}"
                    )
                yield res
