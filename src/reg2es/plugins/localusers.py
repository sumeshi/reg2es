# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Extract the local user list from the SAM database"""

    __REGHIVE__ = "SAM"

    def run(self):
        k = self.open_key("SAM\\Domains\\Account\\Users\\Names")
        if not k:
            return

        for user in k.subkeys():
            res = PluginResult(key=user, value=None)
            yield res
