# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Returns the computer name"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key(
            self.get_currentcontrolset_path() + "\\Control\\ComputerName\\ComputerName"
        )
        if not key:
            return

        compname = key.value("ComputerName")

        res = PluginResult(key=key, value=compname)
        yield res
