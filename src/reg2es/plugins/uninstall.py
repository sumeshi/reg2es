# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; recover independent entries and report local read failures.

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists installed software"""

    __REGHIVE__ = "SOFTWARE"

    def run(self):
        for path in (
            r"Microsoft\Windows\CurrentVersion\Uninstall",
            r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ):
            with self.recover(path, stage="subkeys"):
                key = self.open_key(path)
                if not key:
                    continue
                for program in key.subkeys():
                    with self.recover(program):
                        values = self.read_values(program)
                        display_name = "[N/A]"
                        with self.recover(program, "DisplayName"):
                            try:
                                display_name = self.get_value(
                                    program, "DisplayName", values
                                ).value()
                            except Registry.RegistryValueNotFoundException:
                                pass

                        uninstall_string = "[N/A]"
                        with self.recover(program, "UninstallString"):
                            try:
                                uninstall_string = self.get_value(
                                    program, "UninstallString", values
                                ).value()
                            except Registry.RegistryValueNotFoundException:
                                pass

                        install_date = None
                        with self.recover(program, "InstallDate"):
                            try:
                                install_date = self.get_value(
                                    program, "InstallDate", values
                                ).value()
                            except Registry.RegistryValueNotFoundException:
                                pass

                        res = PluginResult(key=program)
                        res.custom["display_name"] = display_name
                        res.custom["uninstall_string"] = uninstall_string
                        res.custom["install_date_raw"] = install_date
                        res.custom["timestamp_investigation"] = {
                            "status": "unconfirmed",
                            "candidate": "InstallDate",
                            "fallback": "key.last_write",
                            "reason": "date-only values may describe install, update, or repair",
                            "precision": (
                                "date" if isinstance(install_date, str) else "unknown"
                            ),
                        }
                        res.mark_timestamp_fallback(
                            "uninstall_installdate_precision_or_meaning_unconfirmed"
                        )
                        yield res
