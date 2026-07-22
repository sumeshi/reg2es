# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from enum import Enum

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists all services installed on the system"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key(self.get_currentcontrolset_path() + "\\Services")
        if not key:
            return

        for service in key.subkeys():
            values = [x.name() for x in service.values()]

            res = PluginResult(key=service, value=None)
            res.custom = {
                "image_path": service.value("ImagePath").value()
                if "ImagePath" in values
                else "N/A",
                "start_mode": ServiceStartMode(
                    service.value("Start").value() if "Start" in values else -1
                ),
                "description": service.value("Description").value()
                if "Description" in values
                else "N/A",
                "account": service.value("ObjectName").value()
                if "ObjectName" in values
                else "LocalSystem",
            }
            yield res

class ServiceStartMode(Enum):
    AUTOMATIC = 2
    BOOT = 0
    DISABLED = 4
    MANUAL = 3
    SYSTEM = 1
    UNKNOWN = -1

