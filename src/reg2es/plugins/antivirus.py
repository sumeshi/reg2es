# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """gets the default antivirus, and retrieves the status of all installed antiviruses"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        k = self.open_key(r"Microsoft\Security Center\Provider\Av")
        if not k:
            return

        for subkey in k.subkeys():
            r = PluginResult(key=subkey)
            r.custom = {
                "DisplayName": subkey.value("DISPLAYNAME").value(),
                "ProductExe": subkey.value("PRODUCTEXE").value(),
                "ReportingExe": subkey.value("REPORTINGEXE").value(),
                "State": " | ".join(self.parse_state(subkey.value("STATE").value())),
            }
            yield r

    def parse_state(self, state):
        # Source: https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
        enums = []

        if state & 0x3000 == 0x3000:
            enums.append("EXPIRED")
        elif state & 0x2000 == 0x2000:
            enums.append("SNOOZED")
        elif state & 0x1000 == 0x1000:
            enums.append("ON")
        else:
            enums.append("OFF")

        if state & 0x10 == 0x10:
            enums.append("OUT_OF_DATE")
        else:
            enums.append("UP_TO_DATE")

        if state & 0x100 == 0x100:
            enums.append("MICROSOFT_PRODUCT")
        else:
            enums.append("NON_MICROSOFT_PRODUCT")

        return enums

