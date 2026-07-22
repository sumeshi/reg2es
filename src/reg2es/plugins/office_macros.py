# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists all Office files which had macros enabled"""

    __REGHIVE__ = ["NTUSER.DAT"]

    def run(self):
        k = self.open_key("Software\\Microsoft\\Office")
        if not k:
            return

        # Loop over all versions
        for version in k.subkeys():
            try:
                float(version.name())
            except ValueError:
                continue

            # For each version, look for these programs specifically
            for program in ["Word", "Excel", "PowerPoint"]:
                program_key = self.open_key(
                    f"Software\\Microsoft\\Office\\{version.name()}\\{program}\\Security\\Trusted Documents\\TrustRecords"
                )
                if not program_key:
                    continue

                for value in program_key.values():
                    r = PluginResult(key=program_key, value=value)
                    if value.value().endswith(b"\xff\xff\xff\x7f"):
                        yield r
