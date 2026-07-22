# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Reads TeamViewer configuration"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        path = r"TeamViewer"

        k = self.open_key(path)
        if k:
            yield from self.process_key(k)

        k = self.open_key("Wow6432Node\\" + path)
        if k:
            yield from self.process_key(k)

    def process_key(self, k):
        r = PluginResult(key=k)

        values = [x.name() for x in k.values()]

        r.custom = {
            "AlwaysOnline": k.value("Always_Online").value() == 1,
            "ClientID": k.value("ClientID").value(),
            "LastStartupTime": k.value("LastStartupTime")
            if "LastStartupTime" in values
            else -1,
            "Version": k.value("Version").value(),
        }
        yield r
