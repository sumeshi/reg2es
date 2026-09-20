# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.
# Added validated SAM F artifact times, retaining raw values on fallback.

from Registry import Registry

from reg2es.plugins import BasePlugin, PluginResult, filetime_to_datetime

# SAM stores a user's RID in the registry *type* of the Names default value.
# Standard REG_* types (0..11) are never valid RIDs, so they are ignored to
# avoid misreading an unrelated typed value as a RID.
STANDARD_REGISTRY_TYPES = frozenset(range(12))

# The checked real-hive fixture uses this fixed layout.  Do not interpret
# partial records or other revisions using its offsets without verification.
SUPPORTED_F_REVISION = 3
SUPPORTED_F_SIZE = 80


def _f_validation_error(data, rid):
    if not isinstance(data, (bytes, bytearray)):
        return "sam_user_f_invalid_type"
    if len(data) < SUPPORTED_F_SIZE:
        return "sam_user_f_truncated"
    if len(data) != SUPPORTED_F_SIZE:
        return "sam_user_f_unsupported_size"
    if int.from_bytes(data[:2], "little") != SUPPORTED_F_REVISION:
        return "sam_user_f_unsupported_revision"
    if int.from_bytes(data[48:52], "little") != rid:
        return "sam_user_rid_mismatch"
    return None


class Plugin(BasePlugin):
    """Extract the local user list from the SAM database"""

    __REGHIVE__ = "SAM"

    def run(self):
        k = self.open_key("SAM\\Domains\\Account\\Users\\Names")
        if not k:
            return

        for user in k.subkeys():
            res = PluginResult(key=user, value=None)
            rid = None
            for candidate in user.values():
                # SAM stores the RID in the default value's registry type
                # field (commonly 500), not in its data payload.
                if str(candidate.name()).casefold() in ("", "(default)"):
                    value_type = candidate.value_type()
                    if (
                        isinstance(value_type, int)
                        and 0 < value_type <= 0xFFFFFFFF
                        and value_type not in STANDARD_REGISTRY_TYPES
                    ):
                        rid = value_type
                        break
            f_data = None
            rid_key = None
            if rid is not None:
                rid_key = self.open_key(f"SAM\\Domains\\Account\\Users\\{rid:08x}")
                if rid_key:
                    try:
                        f_data = rid_key.value("F").value()
                    except Registry.RegistryValueNotFoundException:
                        f_data = None

            validation_error = (
                _f_validation_error(f_data, rid) if f_data is not None else None
            )

            def sam_time(offset):
                if f_data is None or validation_error is not None:
                    return None
                return filetime_to_datetime(f_data[offset : offset + 8])

            login = sam_time(8)
            password_reset = sam_time(24)
            expiry = sam_time(32)
            failed_login = sam_time(40)
            res.custom["sam_user"] = {
                "rid": rid,
                "f_raw": (
                    bytes(f_data).hex()
                    if isinstance(f_data, (bytes, bytearray))
                    else str(f_data) if f_data is not None else None
                ),
                "last_login": login[1] if login else None,
                "password_reset": password_reset[1] if password_reset else None,
                "account_expiry": expiry[1] if expiry else None,
                "failed_login": failed_login[1] if failed_login else None,
            }
            if login:
                res.set_event_time(
                    login[0],
                    source="SAM.Users.F.last_login",
                    meaning="user_last_login",
                    precision="microseconds",
                    raw=login[1],
                )
            elif rid is None:
                res.mark_timestamp_fallback("sam_user_rid_missing")
            elif f_data is None:
                res.mark_timestamp_fallback("sam_user_f_value_missing")
            elif validation_error is not None:
                res.mark_timestamp_fallback(validation_error)
                self.warning(
                    f"plugin=localusers hive={self.hive_name} path={self.hive_path} "
                    f"{validation_error} for {user.name()}"
                )
            else:
                raw_login = int.from_bytes(f_data[8:16], "little")
                if raw_login in (0, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                    res.mark_timestamp_fallback("sam_user_last_login_sentinel")
                else:
                    res.mark_timestamp_fallback("sam_user_last_login_invalid")
                    self.warning(
                        f"plugin=localusers hive={self.hive_name} path={self.hive_path} "
                        f"invalid last login FILETIME for {user.name()}"
                    )
            yield res
