# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Extracts the user's proxy settings"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        k = self.open_key(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        if not k:
            return

        r = PluginResult(key=k)

        r.custom["type"] = "proxy"
        r.custom["enabled"] = self.safe_value(k, "ProxyEnabled", 0) == 1
        r.custom["proxy"] = self.safe_value(k, "ProxyServer", "N/A")
        r.custom["exceptions"] = self.safe_value(k, "ProxyOverride", "")

        yield r

        r = PluginResult(key=k)
        r.custom["type"] = "autoconfig"
        r.custom["proxypac"] = self.safe_value(k, "AutoConfigURL", "N/A")

        yield r

    def safe_value(self, k, name, default):
        for v in k.values():
            if v.name() == name:
                return v.value()
        return default
