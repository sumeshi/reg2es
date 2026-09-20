# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.
# Added installation-time selection with independent, lossless DWORD reads.

import re
from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime


class Plugin(BasePlugin):
    """get all KB update installation status"""

    __REGHIVE__ = "SOFTWARE"

    STATUS_CODES = {
        0x0: "Absent",
        0x5: "Uninstall pending",
        0x10: "Resolving",
        0x20: "Resolved",
        0x30: "Staging",
        0x40: "Staged",
        0x50: "Superseded",
        0x60: "Install pending",
        0x65: "Partially installed",
        0x70: "Installed",
        0x80: "Permanent",
    }

    def run(self):
        k = self.open_key(
            r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
        )
        if not k:
            return

        r = r"Package(_(?P<pkgnum>[0-9]+))?_for_(?P<kb>KB[0-9]+)"
        for subkey in k.subkeys():
            match = re.match(r, subkey.name())
            if not match:
                continue

            res = PluginResult(key=subkey)
            res.custom["kb"] = match.group("kb")
            res.custom["number"] = match.group("pkgnum")
            res.custom["status_code"] = subkey.value("CurrentState").value()
            res.custom["status"] = self.STATUS_CODES.get(
                res.custom["status_code"], "unknown"
            )
            raw_time = {}
            for part, name in (("high", "InstallTimeHigh"), ("low", "InstallTimeLow")):
                try:
                    raw_time[part] = subkey.value(name).value()
                except Registry.RegistryValueNotFoundException:
                    raw_time[part] = None
            res.custom["install_time_raw"] = raw_time
            high, low = raw_time["high"], raw_time["low"]
            install = None
            if (
                type(high) is int
                and type(low) is int
                and 0 <= high <= 0xFFFFFFFF
                and 0 <= low <= 0xFFFFFFFF
            ):
                filetime = (high << 32) | low
                install = filetime_to_datetime(filetime)
            # InstallTime is meaningful as installation time only for an
            # installed/permanent package; transitional states are retained
            # as raw data and use LastWrite.
            if install and res.custom["status_code"] in (0x70, 0x80):
                res.set_event_time(
                    install[0],
                    source="InstallTimeHigh/InstallTimeLow",
                    meaning="kb_installation",
                    precision="microseconds",
                    raw=install[1],
                )
            elif install:
                res.mark_timestamp_fallback("kb_install_time_state_not_installed")
            elif high is None or low is None:
                # These values are optional; absence is not evidence of damage.
                res.mark_timestamp_fallback("kb_install_time_missing")
            elif type(high) is int and type(low) is int and high == 0 and low == 0:
                res.mark_timestamp_fallback("kb_install_time_sentinel")
            else:
                res.mark_timestamp_fallback("kb_install_time_invalid")
                self.warning(
                    f"plugin=kb hive={self.hive_name} path={self.hive_path} "
                    f"invalid InstallTime for {subkey.name()}"
                )

            yield res
