# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads startup programs from various hives"""

    __REGHIVE__ = ["NTUSER.DAT", "SOFTWARE"]

    def run(self):
        if self.hive_name == "NTUSER.DAT":
            paths = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
            ]
        else:  # SOFTWARE
            paths = [
                r"Microsoft\Windows\CurrentVersion\Run",
                r"Microsoft\Windows\CurrentVersion\RunOnce",
                r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ]

        for path in paths:
            key = self.open_key(path)
            if not key:
                continue

            for v in key.values():
                res = PluginResult(key=key, value=v)
                yield res
