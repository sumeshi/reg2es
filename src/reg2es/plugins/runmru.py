# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads RunMRU key (Most Recently Used programs)"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        key = self.open_key(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        )
        if not key or not key.values():
            return

        order = key.value("MRUList")
        values = dict([(v.name(), v) for v in key.values() if v.name() != "MRUList"])

        for letter in order.value():
            res = PluginResult(key=key, value=values[letter])
            yield res
