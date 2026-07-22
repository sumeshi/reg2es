# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Returns the computer's timezone"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        ccs = self.get_currentcontrolset_path()
        if not ccs:
            return

        key = self.open_key(ccs + r"\Control\TimeZoneInformation")
        if not key:
            return

        value = key.value("TimeZoneKeyName")
        yield PluginResult(key=key, value=value)
