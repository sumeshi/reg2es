# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists all network redirections configured on the system"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        ccs = self.get_currentcontrolset_path()
        if not ccs:
            return

        for proto in ["tcp", "udp"]:
            key = self.open_key(ccs + "\\Services\\PortProxy\\v4tov4\\" + proto)
            if not key:
                continue

            for value in key.values():
                res = PluginResult(key=key, value=value)
                res.custom["proto"] = proto
                yield res
