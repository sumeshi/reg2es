# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; recover independent entries and report local read failures.

from Registry.Registry import RegistryValueNotFoundException

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads TeamViewer configuration"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        for path in (r"TeamViewer", r"Wow6432Node\TeamViewer"):
            with self.recover(path):
                key = self.open_key(path)
                if key:
                    yield from self.process_key(key)

    def process_key(self, k):
        r = PluginResult(key=k)

        values = []
        for value in k.values():
            with self.recover(k, value, stage="name"):
                values.append((value.name(), value))

        startup = None
        with self.recover(k, "LastStartupTime"):
            for name, value in values:
                if name == "LastStartupTime":
                    startup = value.value()
                    break
        r.custom = {
            "AlwaysOnline": self._value(k, values, "Always_Online") == 1,
            "ClientID": self._value(k, values, "ClientID"),
            "LastStartupTime": startup if startup is not None else -1,
            "Version": self._value(k, values, "Version"),
            "timestamp_investigation": {
                "status": "unconfirmed",
                "candidate": "LastStartupTime",
                "fallback": "key.last_write",
            },
        }
        r.mark_timestamp_fallback("teamviewer_startup_time_format_unconfirmed")
        yield r

    @staticmethod
    def _value(key, values, name):
        for value_name, value in values:
            if value_name.lower() == name.lower():
                return value.value()
        raise RegistryValueNotFoundException(key.path() + " : " + name)
