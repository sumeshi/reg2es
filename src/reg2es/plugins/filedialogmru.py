# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads OpenSaveMRU and LastVisitedMRU keys (Most Recently Used files in Save As / Open file dialogs)"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        for path in [
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
        ]:
            key = self.open_key(path)
            if not key or not key.values():
                continue

            order = key.value("MRUList").value()
            values = dict(
                [(v.name(), v) for v in key.values() if v.name() != "MRUList"]
            )

            for letter in order:
                yield PluginResult(key=key, value=values[letter])
