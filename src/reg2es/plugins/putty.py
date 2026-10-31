# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers
# removed; recover independent entries and report local read failures.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists information about PuTTY connections: saved public keys, saved sessions, etc."""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        root = r"Software\SimonTatham\PuTTY"
        path = root + r"\SshHostKeys"
        with self.recover(path, stage="values"):
            key = self.open_key(path)
            if key:
                for value in key.values():
                    with self.recover(key, value):
                        crypto, host = value.name().split("@")
                        result = PluginResult(key=key, value=value)
                        result.custom["type"] = "sshkey"
                        result.custom["crypto"] = crypto
                        result.custom["host"] = host
                        yield result

        path = root + r"\Sessions"
        with self.recover(path, stage="subkeys"):
            sessions = self.open_key(path)
            if not sessions:
                return
            for session in sessions.subkeys():
                with self.recover(session):
                    values = self.read_values(session)
                    host = self.get_value(session, "HostName", values).value()
                    protocol = self.get_value(session, "Protocol", values).value()
                    result = PluginResult(key=session)
                    result.custom["type"] = "session"
                    result.custom["host"] = host
                    result.custom["protocol"] = protocol
                    yield result
