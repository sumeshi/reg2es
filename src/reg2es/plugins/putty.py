# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry.Registry import (
    RegistryKeyNotFoundException,
    RegistryValueNotFoundException,
)

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists information about PuTTY connections: saved public keys, saved sessions, etc."""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        k = self.open_key(r"Software\SimonTatham\PuTTY")
        if not k:
            return

        # SSH host keys
        try:
            ssh_host_keys = k.subkey("SshHostKeys")
            for v in ssh_host_keys.values():
                name = v.name()
                crypto, host = name.split("@")

                r = PluginResult(key=ssh_host_keys, value=v)
                r.custom["type"] = "sshkey"
                r.custom["crypto"] = crypto
                r.custom["host"] = host

                yield r
        except RegistryKeyNotFoundException:
            self.warning("Could not find SshHostKeys subkey")

        # Saved sessions
        try:
            sessions = k.subkey("Sessions")
            for sess in sessions.subkeys():
                try:
                    name = sess.name()
                    host = sess.value("HostName").value()
                    proto = sess.value("Protocol").value()

                    r = PluginResult(key=sess)
                    r.custom["type"] = "session"
                    r.custom["host"] = host
                    r.custom["protocol"] = proto

                    yield r
                except RegistryValueNotFoundException:
                    self.warning(f"Malformed entry: {sess.name()}")
        except RegistryKeyNotFoundException:
            self.warning("Could not find Sessions subkey")
