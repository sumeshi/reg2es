# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

from Registry.Registry import RegistryValueNotFoundException

from reg2es.plugins import BasePlugin, PluginResult

# Based on the information in libyal/winreg-kb
# https://github.com/libyal/winreg-kb/blob/main/docs/sources/system-keys/Environment-variables.md


class Plugin(BasePlugin):
    """Lists all environment variables"""

    __REGHIVE__ = ["SYSTEM", "SOFTWARE", "NTUSER.DAT"]

    def run(self):
        if self.hive_name == "SYSTEM":
            yield from self.handle_env_key()
        elif self.hive_name == "SOFTWARE":
            yield from self.handle_windows_currentversion()
            yield from self.handle_windows_nt_currentversion()
            yield from self.handle_profilelist()
        elif self.hive_name == "NTUSER.DAT":
            yield from self.handle_user_env()

    def handle_env_key(self):
        ccs = self.get_currentcontrolset_path()
        k = self.open_key(ccs + "\\Control\\Session Manager\\Environment")
        if not k:
            return

        for v in k.values():
            r = PluginResult(key=k, value=v)

            r.custom["Name"] = f"%{v.name()}%"
            yield r

    def handle_windows_currentversion(self):
        k = self.open_key("Microsoft\\Windows\\CurrentVersion")
        if not k:
            return

        try:
            v = k.value("CommonFilesDir")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%CommonProgramFiles%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("CommonFilesDir (x86)")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%CommonProgramFiles(x86)%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("CommonW6432Dir")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%CommonProgramW6432%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("ProgramFilesDir")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%ProgramFiles%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("ProgramFilesDir (x86)")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%ProgramFiles(x86)%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("ProgramW6432Dir")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%ProgramW6432%"
            yield r
        except RegistryValueNotFoundException:
            pass

    def handle_windows_nt_currentversion(self):
        k = self.open_key("Microsoft\\Windows NT\\CurrentVersion")
        if not k:
            return

        try:
            v = k.value("SystemRoot")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%SystemRoot%"
            yield r
        except RegistryValueNotFoundException:
            pass

    def handle_profilelist(self):
        k = self.open_key("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        if not k:
            return

        try:
            v = k.value("ProgramData")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%ProgramData%"
            yield r
        except RegistryValueNotFoundException:
            pass

        try:
            v = k.value("Public")
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = "%Public%"
            yield r
        except RegistryValueNotFoundException:
            pass

    def handle_user_env(self):
        k = self.open_key("Environment")
        if not k:
            return

        for v in k.values():
            r = PluginResult(key=k, value=v)
            r.custom["Name"] = f"%{v.name()}%"
            yield r
