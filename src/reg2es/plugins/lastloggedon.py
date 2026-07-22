# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Gets the name of the last logged-on user"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        key = self.open_key(
            "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
        )
        if not key:
            return

        for v in key.values():
            if (
                v.name().startswith("LastLoggedOn")
                and v.name() != "LastLoggedOnProvider"
            ):
                res = PluginResult(key=key, value=v)
                yield res
