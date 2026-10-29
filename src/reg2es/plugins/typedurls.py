# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime


class Plugin(BasePlugin):
    """Extracts URLs typed into Internet Explorer"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        path = r"Software\Microsoft\Internet Explorer\TypedURLs"
        with self.recover(path, stage="values"):
            key = self.open_key(path)
            if not key:
                return
            values = key.values()
            yield from self._records(key, values)

    def _records(self, key, values):
        time_path = r"Software\Microsoft\Internet Explorer\TypedURLsTime"
        time_values = {}
        with self.recover(time_path, stage="values"):
            time_key = self.open_key(time_path)
            if time_key:
                for value in time_key.values():
                    with self.recover(time_key, value):
                        time_values[value.name().casefold()] = value

        self.info(self.guess_username())
        for v in values:
            with self.recover(key, v):
                yield self._record(key, v, time_values)

    def _record(self, key, value, time_values):
        res = PluginResult(key=key, value=value)
        time_value = time_values.get(value.name().casefold())
        if time_value is None:
            res.mark_timestamp_fallback("typedurls_time_missing")
        else:
            res.mark_timestamp_fallback("invalid_typedurls_time")
            with self.recover(
                r"Software\Microsoft\Internet Explorer\TypedURLsTime",
                time_value,
                stage="timestamp",
            ):
                self._timestamp(res, value, time_value)
        return res

    def _timestamp(self, res, v, time_value):
        try:
            raw_time = time_value.value()
        except Exception:
            # Native decoding may fail while the original Registry bytes are
            # still readable. Keep those bytes with the recovered URL.
            try:
                res.custom["typedurls_time_raw"] = time_value.raw_data().hex()
            except Exception:
                pass
            raise
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
            res.mark_timestamp_fallback(
                "typedurls_time_missing"
                if raw_time == b"\0" * 8
                else "invalid_typedurls_time"
            )
            if raw_time != b"\0" * 8:
                self.warning(
                    f"plugin=typedurls hive={self.hive_name} path={self.hive_path} "
                    f"invalid TypedURLsTime for {v.name()}"
                )
