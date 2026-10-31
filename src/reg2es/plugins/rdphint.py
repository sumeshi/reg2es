# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; recover independent entries and report local read failures.

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists the recently connected to RDP servers"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        path = r"Software\Microsoft\Terminal Server Client\Servers"
        with self.recover(path, stage="subkeys"):
            key = self.open_key(path)
            if not key:
                return
            for subkey in key.subkeys():
                with self.recover(subkey):
                    username = ""
                    with self.recover(subkey, "UsernameHint"):
                        try:
                            username = self.get_value(subkey, "UsernameHint").value()
                        except Registry.RegistryValueNotFoundException:
                            pass
                    result = PluginResult(key=subkey, value=None)
                    result.custom["username"] = username
                    yield result
