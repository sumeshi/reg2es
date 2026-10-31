"""Extract USB mass-storage device instances recorded by the SYSTEM hive."""

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Emit each USBSTOR hardware instance with its raw registry values."""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        control_set = self.get_currentcontrolset_path()
        if not control_set:
            return
        path = f"{control_set}\\Enum\\USBSTOR"
        with self.recover(path, stage="subkeys"):
            root = self.open_key(path)
            if not root:
                return
            for device_type in root.subkeys():
                with self.recover(device_type, stage="subkeys"):
                    for instance in device_type.subkeys():
                        with self.recover(instance):
                            result = PluginResult(key=instance)
                            result.custom["device_type"] = device_type.name()
                            result.custom["instance_id"] = instance.name()
                            values = {}
                            for value in instance.values():
                                with self.recover(instance, value):
                                    values[value.name()] = value.value()
                            result.custom["registry_values"] = values
                            yield result
