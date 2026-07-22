# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry.Registry import RegistryValueNotFoundException

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """list all GPOs applied on this system"""

    __REGHIVE__ = ["SOFTWARE", "NTUSER.DAT"]

    EXTENSIONS = {
        "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry Settings",
    }

    def run(self):
        path = r"Microsoft\Windows\CurrentVersion\Group Policy\History"
        if self.hive_name == "NTUSER.DAT":
            path = "SOFTWARE\\" + path
        else:
            self.get_gp_extensions()

        k = self.open_key(path)
        if not k:
            return

        for subkey in k.subkeys():
            for gpo in subkey.subkeys():
                r = PluginResult(key=gpo)
                r.custom = {
                    "Extension": self.EXTENSIONS.get(subkey.name(), subkey.name()),
                    "DisplayName": gpo.value("DisplayName").value(),
                    "DSPath": (
                        gpo.value("DSPath").value()
                        if "DSPath" in [x.name() for x in gpo.values()]
                        else "N/A"
                    ),
                    "Path": gpo.value("FileSysPath").value(),
                    "GPOName": gpo.value("GPOName").value(),
                    "IParam": (
                        gpo.value("IParam").value()
                        if "IParam" in [x.name() for x in gpo.values()]
                        else "N/A"
                    ),
                    "Options": (
                        gpo.value("Options").value()
                        if "Options" in [x.name() for x in gpo.values()]
                        else "N/A"
                    ),
                }
                yield r

    def get_gp_extensions(self):
        k = self.open_key(r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions")
        if not k:
            return

        for subkey in k.subkeys():
            guid = subkey.name()
            if guid in self.EXTENSIONS.keys():
                continue

            name = guid
            try:
                name = subkey.value("(default)").value()
            except RegistryValueNotFoundException:
                pass
            self.EXTENSIONS[guid] = name
