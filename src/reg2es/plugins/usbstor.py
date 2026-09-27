"""Extract USB mass-storage device instances recorded by the SYSTEM hive."""

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Emit each USBSTOR hardware instance with its raw registry values."""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        control_set = self.get_currentcontrolset_path()
        if not control_set:
            return
        root = self.open_key(f"{control_set}\\Enum\\USBSTOR")
        if not root:
            return

        for device_type in root.subkeys():
            for instance in device_type.subkeys():
                result = PluginResult(key=instance)
                result.custom["device_type"] = device_type.name()
                result.custom["instance_id"] = instance.name()
                values = {}
                for value in instance.values():
                    values[value.name()] = value.value()
                result.custom["registry_values"] = values
                yield result
