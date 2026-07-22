# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists the recently connected to RDP servers"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        key = self.open_key(r"Software\Microsoft\Terminal Server Client\Servers")
        if not key:
            return

        for subkey in key.subkeys():
            try:
                username = subkey.value("UsernameHint").value()
            except Registry.RegistryValueNotFoundException:
                username = ""

            res = PluginResult(key=subkey, value=None)
            res.custom["username"] = username
            yield res
