# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Extracts URLs typed into Internet Explorer"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        key = self.open_key(r"Software\Microsoft\Internet Explorer\TypedURLs")
        if not key:
            return

        self.info(self.guess_username())
        for v in key.values():
            res = PluginResult(key=key, value=v)
            yield res
