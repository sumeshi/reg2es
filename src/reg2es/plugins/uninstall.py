# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists installed software"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        key = self.open_key("Microsoft\\Windows\\CurrentVersion\\Uninstall")
        if not key:
            return

        for program in key.subkeys():
            try:
                display_name = program.value("DisplayName").value()
            except Registry.RegistryValueNotFoundException:
                display_name = "[N/A]"

            try:
                uninstall_string = program.value("UninstallString").value()
            except Registry.RegistryValueNotFoundException:
                uninstall_string = "[N/A]"

            try:
                install_date = program.value("InstallDate").value()
            except Registry.RegistryValueNotFoundException:
                install_date = None

            res = PluginResult(key=program)
            res.custom["display_name"] = display_name
            res.custom["uninstall_string"] = uninstall_string
            res.custom["install_date_raw"] = install_date
            res.custom["timestamp_investigation"] = {
                "status": "unconfirmed",
                "candidate": "InstallDate",
                "fallback": "key.last_write",
                "reason": "date-only values may describe install, update, or repair",
                "precision": "date" if isinstance(install_date, str) else "unknown",
            }
            res.mark_timestamp_fallback(
                "uninstall_installdate_precision_or_meaning_unconfirmed"
            )
            yield res
