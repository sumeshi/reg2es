# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; report individual value failures while recovering later entries.

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
            try:
                key = self.open_key(path)
                if not key:
                    continue
                path = key.path()
                values = key.values()
            except Exception as exc:
                self.record_error(path, None, exc, stage="values")
                continue

            for value in values:
                name = None
                try:
                    name = value.name()
                    res = PluginResult(key=key, value=value)
                except Exception as exc:
                    self.record_error(path, name, exc, stage="record")
                    continue
                yield res
