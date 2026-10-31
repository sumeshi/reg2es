# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from enum import Enum

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists all services installed on the system"""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key(self.get_currentcontrolset_path() + "\\Services")
        if not key:
            return

        for service in key.subkeys():
            key_path, value_name = "<unreadable>", None
            errors_before = len(self.errors)
            try:
                key_path = service.path()
                values = self.read_values(service)
                res = PluginResult(key=service, value=None)
                for name, field, default in (
                    ("ImagePath", "image_path", "N/A"),
                    ("Start", "start_mode", -1),
                    ("Description", "description", "N/A"),
                    ("ObjectName", "account", "LocalSystem"),
                ):
                    value_name = name
                    raw = default
                    try:
                        raw = self.get_value(service, name, values).value()
                    except Registry.RegistryValueNotFoundException:
                        pass
                    if name == "Start":
                        try:
                            value = ServiceStartMode(raw)
                        except ValueError:
                            value = ServiceStartMode.UNKNOWN
                            res.custom["start_mode_raw"] = raw
                            self.warning(
                                f"plugin=services hive={self.hive_name} "
                                f"path={self.hive_path} key={key_path} "
                                "value=Start "
                                f"unknown start mode: {raw!r}"
                            )
                    else:
                        value = raw
                    res.custom[field] = value
            except Exception as exc:
                if self.error_policy == "raise" and len(self.errors) > errors_before:
                    raise
                self.record_error(key_path, value_name, exc)
                continue
            yield res


class ServiceStartMode(Enum):
    AUTOMATIC = 2
    BOOT = 0
    DISABLED = 4
    MANUAL = 3
    SYSTEM = 1
    UNKNOWN = -1
