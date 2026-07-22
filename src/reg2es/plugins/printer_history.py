# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult

# The entries in "ConvertUserDevModesCount" are not removed when a printer is deleted


class Plugin(BasePlugin):
    """Lists all printers that were connected to this machine"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        k = self.open_key(r"Printers\ConvertUserDevModesCount")
        if not k:
            return

        for v in k.values():
            r = PluginResult(key=k, value=v)
            yield r
