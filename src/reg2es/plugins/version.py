# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Get the Windows version"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        key = self.open_key("Microsoft\\Windows NT\\CurrentVersion")
        if not key:
            return

        value = key.value("ProductName")
        yield PluginResult(key=key, value=value)
