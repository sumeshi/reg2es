# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

import re

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """get all KB update installation status"""

    __REGHIVE__ = "SOFTWARE"

    STATUS_CODES = {
        0x0: "Absent",
        0x5: "Uninstall pending",
        0x10: "Resolving",
        0x20: "Resolved",
        0x30: "Staging",
        0x40: "Staged",
        0x50: "Superseded",
        0x60: "Install pending",
        0x65: "Partially installed",
        0x70: "Installed",
        0x80: "Permanent",
    }

    def run(self):
        k = self.open_key(
            r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        )
        if not k:
            return

        r = r"Package(_(?P<pkgnum>[0-9]+))?_for_(?P<kb>KB[0-9]+)"
        for subkey in k.subkeys():
            match = re.match(r, subkey.name())
            if not match:
                continue

            res = PluginResult(key=subkey)
            res.custom["kb"] = match.group("kb")
            res.custom["number"] = match.group("pkgnum")
            res.custom["status_code"] = subkey.value("CurrentState").value()
            res.custom["status"] = self.STATUS_CODES.get(
                res.custom["status_code"], "unknown"
            )

            yield res
