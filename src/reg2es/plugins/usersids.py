# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

# Plugin written by Tim Taylor, timtaylor3@yahoo.com
from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Returns the user names with sids"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        path = r"Microsoft\Windows NT\CurrentVersion\ProfileList"
        with self.recover(path, stage="subkeys"):
            key = self.open_key(path)
            if not key:
                return

            for key2 in key.subkeys():
                with self.recover(key2, stage="values"):
                    for entry in key2.values():
                        with self.recover(key2, entry):
                            if entry.name() == "ProfileImagePath":
                                res = PluginResult(key=key2, value=entry)
                                user_name = entry.value().split("\\")[-1]
                                res.custom["value"] = "{}:\t{}".format(
                                    user_name, key2.name()
                                )
                                yield res
