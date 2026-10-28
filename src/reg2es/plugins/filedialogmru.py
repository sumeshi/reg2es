# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; report individual MRU failures while recovering later entries.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads OpenSaveMRU and LastVisitedMRU keys (Most Recently Used files in Save As / Open file dialogs)"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        for path in [
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
        ]:
            try:
                key = self.open_key(path)
                if not key:
                    continue
                path = key.path()
                entries = key.values()
                if not entries:
                    continue
                order = iter(key.value("MRUList").value())
                values = {v.name(): v for v in entries if v.name() != "MRUList"}
            except Exception as exc:
                self.record_error(path, None, exc, stage="values")
                continue

            for letter in order:
                try:
                    res = PluginResult(key=key, value=values[letter])
                except Exception as exc:
                    self.record_error(path, letter, exc, stage="record")
                    continue
                yield res
