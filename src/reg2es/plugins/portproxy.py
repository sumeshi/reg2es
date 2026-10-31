# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; recover independent entries and report local read failures.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists all network redirections configured on the system"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        ccs = self.get_currentcontrolset_path()
        if not ccs:
            return

        for family in ("v4tov4", "v4tov6", "v6tov4", "v6tov6"):
            for proto in ("tcp", "udp"):
                path = f"{ccs}\\Services\\PortProxy\\{family}\\{proto}"
                with self.recover(path, stage="values"):
                    key = self.open_key(path)
                    if not key:
                        continue
                    for value in key.values():
                        with self.recover(key, value):
                            result = PluginResult(key=key, value=value)
                            result.custom["proto"] = proto
                            yield result
