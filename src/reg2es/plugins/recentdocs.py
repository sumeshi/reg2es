# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed;
# UTF-16LE strings are terminated on code-unit boundaries.

from reg2es.plugins import BasePlugin, PluginResult


class Plugin(BasePlugin):
    """Lists 'My Recent Documents'"""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        key = self.open_key(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        )
        if not key:
            return

        for v in key.values():
            if v.name() == "MRUListEx":
                continue

            binary = v.value()
            offset_str_end = next(
                (
                    offset
                    for offset in range(0, len(binary) - 1, 2)
                    if binary[offset : offset + 2] == b"\x00\x00"
                ),
                None,
            )
            if offset_str_end is None:
                # Some hives contain a truncated terminator. Preserve the
                # upstream parser's tolerance while keeping an even length.
                fallback_end = binary.find(b"\x00\x00")
                offset_str_end = (
                    len(binary)
                    if fallback_end < 0
                    else fallback_end + (fallback_end % 2)
                )
            docname = binary[:offset_str_end].decode("utf-16le", "replace")

            res = PluginResult(key=key, value=v)
            res.custom["docname"] = docname
            yield res
