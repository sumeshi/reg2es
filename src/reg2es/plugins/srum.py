# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Gets the temporary SRUM data from the registry"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        path = "Microsoft\\Windows\\CurrentVersion\\SRUM\\Extensions\\"
        with self.recover(path, stage="subkeys"):
            key = self.open_key(path)
            if not key:
                return

            for extension_key in key.subkeys():
                with self.recover(extension_key, "(default)"):
                    v = self.get_value(extension_key, "(default)")
                    res = PluginResult(key=extension_key, value=v)
                    yield res
