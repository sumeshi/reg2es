# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime


class Plugin(BasePlugin):
    """Extracts URLs typed into Internet Explorer"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        key = self.open_key(r"Software\Microsoft\Internet Explorer\TypedURLs")
        if not key:
            return
        time_key = self.open_key(r"Software\Microsoft\Internet Explorer\TypedURLsTime")

        self.info(self.guess_username())
        values = list(key.values())
        time_values = (
            {v.name().casefold(): v for v in time_key.values()} if time_key else {}
        )
        for v in values:
            # TypedURLsTime is a sibling key.  Its value name matches the URL
            # value name (for example url1), so never infer a synthetic
            # ``url1time`` name in the URL key itself.
            res = PluginResult(key=key, value=v)
            time_value = time_values.get(v.name().casefold())
            if time_value is not None:
                raw_time = time_value.value()
                # The shared converter returns None for sentinel/short/malformed
                # values instead of raising, so a None result is the only
                # failure path.
                parsed = (
                    filetime_to_datetime(raw_time)
                    if isinstance(raw_time, (bytes, bytearray)) and len(raw_time) == 8
                    else None
                )
                if parsed:
                    res.set_event_time(
                        parsed[0],
                        source="TypedURLsTime",
                        meaning="url_typed",
                        precision="microseconds",
                        raw=parsed[1],
                    )
                else:
                    res.custom["typedurls_time_raw"] = (
                        bytes(raw_time).hex()
                        if isinstance(raw_time, (bytes, bytearray))
                        else raw_time
                    )
                    res.mark_timestamp_fallback("invalid_typedurls_time")
                    self.warning(
                        f"plugin=typedurls hive={self.hive_name} path={self.hive_path} "
                        f"invalid TypedURLsTime for {v.name()}"
                    )
            else:
                res.mark_timestamp_fallback("typedurls_time_missing")
            yield res
