# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Produces a timeline of every key's last modification date"""

    __REGHIVE__ = "ALL"

    def run(self):
        key = self.reg.root()

        yield from self.dump(key)

    def dump(self, key):
        res = PluginResult(key=key)
        res.path = self.cleanup_path(res.path)
        yield res

        for subkey in key.subkeys():
            yield from self.dump(subkey)

    def cleanup_path(self, s):
        parts = s.split("\\")[1:]
        hive_path = self.reg.hive_name()
        hive_name = hive_path.split("\\")[-1]
        return hive_name + "\\" + "\\".join(parts)
