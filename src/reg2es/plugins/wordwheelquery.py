"""Extract Explorer search-bar history from a user's WordWheelQuery key."""

import struct

from reg2es.plugins import BasePlugin, PluginResult


def _mru_order(value):
    """Decode the little-endian DWORD order list, stopping at its sentinel."""
    if not isinstance(value, (bytes, bytearray)) or len(value) % 4:
        return []
    order = []
    for (entry,) in struct.iter_unpack("<I", value):
        if entry == 0xFFFFFFFF:
            break
        order.append(str(entry))
    return order


def _decode_search(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return None
    return None


class Plugin(BasePlugin):
    """Emit one result for each stored search term, preserving its raw value."""

    __REGHIVE__ = "NTUSER.DAT"

    def run(self):
        path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
        with self.recover(path, stage="values"):
            key = self.open_key(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
            )
            if not key:
                return

            values = []
            for value in key.values():
                with self.recover(key, value, stage="name"):
                    values.append((value, value.name()))
            mru_value = next(
                (value for value, name in values if name.casefold() == "mrulistex"),
                None,
            )
            order = []
            if mru_value:
                with self.recover(key, mru_value, stage="metadata"):
                    order = _mru_order(mru_value.value())
            for value, name in values:
                with self.recover(key, value):
                    if name.casefold() == "mrulistex":
                        continue
                    result = PluginResult(key=key, value=value)
                    result.custom["mru_index"] = name
                    result.custom["mru_order"] = order
                    decoded = _decode_search(value.value())
                    if decoded is not None:
                        result.custom["search_term"] = decoded
                    yield result
