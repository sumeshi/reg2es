# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry.Registry import RegistryValueNotFoundException

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Extracts the user's proxy settings"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with self.recover(path, stage="values"):
            k = self.open_key(path)
            if not k:
                return
            yield from self._records(k)

    def _records(self, k):
        values = self.read_values(k)

        r = PluginResult(key=k)

        r.custom["type"] = "proxy"
        failures = len(self.errors)
        enabled = self.safe_value(k, "ProxyEnable", 0, values)
        r.custom["enabled"] = None if len(self.errors) > failures else enabled == 1
        r.custom["proxy"] = self.safe_value(k, "ProxyServer", "N/A", values)
        r.custom["exceptions"] = self.safe_value(k, "ProxyOverride", "", values)

        yield r

        r = PluginResult(key=k)
        r.custom["type"] = "autoconfig"
        r.custom["proxypac"] = self.safe_value(k, "AutoConfigURL", "N/A", values)

        yield r

    def safe_value(self, k, name, default, values=None):
        with self.recover(k, name):
            try:
                return self.get_value(k, name, values).value()
            except RegistryValueNotFoundException:
                return default
        return None
