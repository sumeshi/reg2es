# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; report individual MRU failures while recovering later entries.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads RunMRU key (Most Recently Used programs)"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        errors_before = len(self.errors)
        try:
            key = self.open_key(path)
            if not key:
                return
            path = key.path()
            entries = self.read_values(key)
            if not entries:
                return
            order = iter(self.get_value(key, "MRUList", entries).value())
            values = {name: value for name, value in entries if name != "MRUList"}
        except Exception as exc:
            if self.error_policy == "raise" and len(self.errors) > errors_before:
                raise
            self.record_error(path, None, exc, stage="values")
            return

        for letter in order:
            try:
                res = PluginResult(key=key, value=values[letter])
            except Exception as exc:
                self.record_error(path, letter, exc, stage="record")
                continue
            yield res
