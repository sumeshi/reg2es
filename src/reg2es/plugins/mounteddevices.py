"""Extract raw drive-letter and volume mappings from SYSTEM\\MountedDevices."""

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Emit each MountedDevices value without guessing its binary encoding."""

    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key("MountedDevices")
        if not key:
            return
        for value in key.values():
            yield PluginResult(key=key, value=value)
