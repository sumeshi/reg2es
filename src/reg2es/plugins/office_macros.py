# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

import struct

from reg2es.plugins import BasePlugin, PluginResult


def _office_enabled_time(value):
    """Decode TrustRecordEntry.ts_enabled (minutes since the Unix epoch).

    TrustRecordEntry is a 24-byte record; the DWORD at offset 16 is the
    minute-precision time at which editing/macros were enabled.  The layout
    follows dissect.target's ``TrustRecords`` parser and PS-TrustedDocuments.
    """
    if not isinstance(value, (bytes, bytearray)) or len(value) != 24:
        return None
    enabled = struct.unpack_from("<I", value, 16)[0]
    if enabled == 0:
        return None
    unix = enabled * 60
    if unix <= 0:
        return None
    return unix, enabled


class Plugin(BasePlugin):
    """Lists all Office files which had macros enabled"""

    __REGHIVE__ = ["NTUSER.DAT"]

    def run(self):
        k = self.open_key("Software\\Microsoft\\Office")
        if not k:
            return

        # Loop over all versions
        for version in k.subkeys():
            try:
                float(version.name())
            except ValueError:
                continue

            # For each version, look for these programs specifically
            for program in ["Word", "Excel", "PowerPoint"]:
                program_key = self.open_key(
                    f"Software\\Microsoft\\Office\\{version.name()}\\{program}\\Security\\Trusted Documents\\TrustRecords"
                )
                if not program_key:
                    continue

                for value in program_key.values():
                    raw = value.value()
                    if not isinstance(raw, (bytes, bytearray)):
                        continue
                    if not raw.endswith(b"\xff\xff\xff\x7f"):
                        continue
                    r = PluginResult(key=program_key, value=value)
                    parsed = _office_enabled_time(raw)
                    r.custom["trust_record"] = {
                        "format": "TrustRecordEntry/24",
                        "ts_enabled_raw": parsed[1] if parsed else None,
                        "raw": raw,
                    }
                    if parsed:
                        r.set_event_time(
                            parsed[0],
                            source="TrustRecords.ts_enabled",
                            meaning="office_document_macros_enabled",
                            precision="minute",
                            raw=parsed[1],
                        )
                    else:
                        r.mark_timestamp_fallback(
                            "office_trustrecords_enabled_time_invalid"
                        )
                        self.warning(
                            f"plugin=office_macros hive={self.hive_name} path={self.hive_path} "
                            f"invalid TrustRecord for {value.name()}"
                        )
                    yield r
