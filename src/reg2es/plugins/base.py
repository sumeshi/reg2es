# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: imports adapted to reg2es.plugins; unused CLI display helpers removed.

import struct
from datetime import datetime, timedelta, timezone

from Registry import Registry

UNIX_EPOCH_FILETIME = 116444736000000000


def filetime_to_datetime(value):
    """Return ``(UTC datetime, raw FILETIME)`` or ``None`` for invalid data.

    Values before the Unix epoch (for example the 1601/0 sentinels) are
    rejected; this is intentional for artifact times and is not a general
    purpose FILETIME decoder.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        if len(value) != 8:
            return None
        value = struct.unpack("<Q", bytes(value))[0]
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < UNIX_EPOCH_FILETIME:
        return None
    seconds, remainder = divmod(value, 10_000_000)
    try:
        timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=seconds, microseconds=remainder // 10
        )
    except (OverflowError, ValueError):
        return None
    return timestamp, value


def mactime(
    md5="0",
    name="",
    inode=0,
    mode_as_string="",
    uid=0,
    gid=0,
    size=0,
    atime=-1,
    mtime=-1,
    ctime=-1,
    btime=-1,
):
    """Formats and returns a Bodyfile-format line.
    All parameters are optional
    """

    return "|".join(
        [
            md5,
            # remove newlines from the name. There are cases where newlines
            # occur in registry key names, but their occurance breaks the
            # bodyfile format, so we escape them here
            name.replace("\n", "\\n").replace("\r", "\\r"),
            str(inode),
            mode_as_string,
            str(uid),
            str(gid),
            str(size),
            str(atime),
            str(mtime),
            str(ctime),
            str(btime),
        ]
    )


class BasePlugin(object):
    """
    Base class for all plugins. Provides several methods that can be used by plugins
    to perform common actions, like opening registry keys.

    :cvar str_or_list __REGHIVE__: The registry hive (or list thereof) you plugin works on

    :ivar Registry.Registry reg: a handle to a Registry hive
    :ivar logging.Logger logger: a preconfigured Logger. Use the :func:`~BasePlugin.info`, :func:`~BasePlugin.warning` and :func:`~BasePlugin.error` methods instead.
    :ivar str hive_name: the name of the hive. It will always be one of the values in `__REGHIVE__` (see :doc:`createplugin`)
    :ivar str hive_path: the full path to the hive file. Can be "-" if the hive was loaded from `stdin`.
    """

    def __init__(self, reg, logger, hive_name, hive_path):
        self.reg = reg
        self.logger = logger
        self.hive_name = hive_name
        self.hive_path = hive_path

    def run(self):
        """Main entry point of the plugin"""
        raise NotImplementedError("run() needs to be overriden")

    def open_key(self, path):
        """Opens and returns a registry key

        :param path: the full path to a registry key
        :type path: str

        :returns: the key if it was found, otherwise `None`
        :rtype: Registry.RegistryKey
        """
        try:
            key = self.reg.open(path)
            return key
        except Registry.RegistryKeyNotFoundException:
            # A missing key normally means that this plugin does not apply to
            # this particular Windows installation, so it is not actionable.
            return None

    def get_currentcontrolset_path(self):
        """Fetches the path to CurrentControlSet

        :returns: the path to the `CurrentControlSet` key, or `None` if an error happened
        :rtype: str
        """
        select_key = self.open_key("Select")
        if not select_key:
            return None

        current = select_key.value("Current").value()
        ccs_keyname = "ControlSet00" + str(current)

        return ccs_keyname

    def guess_username(self, default=""):
        """Tries to guess the user the current NTUSER.DAT hive corresponds to

        :param default: what to return in case we couldn't determine the user name
        :type default: any type

        :returns: the user name, or `default` if it wasn't found
        :rtype: str
        """

        # Given the following path to a hive
        # \\Users\\JohnDoe\\NTUSER.DAT
        #          ^^^^^^^
        #           we want this part

        parts = self.reg.hive_name().split("\\")

        if len(parts) < 2:
            return default
        return parts[-2]

    def warning(self, msg):
        """Logs a message at WARNING level"""
        self.logger.warning(msg)

    def error(self, msg):
        """Logs a message at ERROR level"""
        self.logger.error(msg)

    def info(self, msg):
        """Logs a message at INFO level"""
        self.logger.info(msg)


class PluginResult(object):
    """A class which holds a single result of a plugin execution

    :ivar dict custom: a `dict` you can use to store custom data for your result
    :ivar int mtime: the "last-modified" time. Automatically set if you pass the `key` parameter.
    :ivar int atime: the "last-accessed" time.
    :ivar int ctime: the "last-changed" time.
    :ivar int btime": the "created" time.
    :ivar str path: complete path to the key. Automatically set if you pass the `key` parameter.
    :ivar str key_name: last part of the key path. Automatically set if you pass the `key` parameter
    :ivar str value_type: the value type
    :ivar str value_name: the name of the Value
    :ivar value_data: the actual value data. The variable type depends on the type of the value.
    """

    def __init__(self, *, key=None, value=None):
        self._key = key
        self._value = value

        self.custom = {}

        self.path = None
        # Keep sub-second precision.  This is the registry key LastWrite and
        # must remain separate from an artifact/event timestamp.
        self.mtime = 0
        self.atime = 0
        self.ctime = 0
        self.btime = 0
        self.value_type = None
        self.value_name = None
        self.value_data = None
        self.event_time = None
        self.event_time_source = None
        self.event_time_meaning = None
        self.event_time_precision = None
        self.event_time_raw = None
        # Plugins with no artifact time inherit this explicit contract-level
        # reason; plugins can replace it with a format-specific reason.
        self.timestamp_fallback_reason = "intrinsic_time_unavailable"

        if key:
            self.path = key.path()
            key_timestamp = key.timestamp()
            if isinstance(key_timestamp, datetime):
                if key_timestamp.tzinfo is None:
                    key_timestamp = key_timestamp.replace(tzinfo=timezone.utc)
                else:
                    key_timestamp = key_timestamp.astimezone(timezone.utc)
                self.mtime = key_timestamp.timestamp()
            elif callable(getattr(key_timestamp, "timestamp", None)):
                self.mtime = key_timestamp.timestamp()
            else:
                self.mtime = key_timestamp
            self.key_name = key.name()

        if value:
            self.value_name = value.name()
            self.value_type = value.value_type_str()
            self.value_data = value.value()

    def set_event_time(
        self,
        value,
        *,
        source,
        meaning,
        precision=None,
        raw=None,
    ):
        """Attach a plugin-parsed artifact time without changing LastWrite."""
        self.event_time = value
        self.event_time_source = source
        self.event_time_meaning = meaning
        self.event_time_precision = precision
        self.event_time_raw = value if raw is None else raw

    def mark_timestamp_fallback(self, reason):
        """Record why this result has no usable intrinsic artifact time."""
        self.timestamp_fallback_reason = reason
