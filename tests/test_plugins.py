"""Package-level checks for the bundled plugin inventory."""

from __future__ import annotations

import importlib
import pkgutil

import reg2es.plugins as plugins

PLUGIN_NAMES = [
    "antivirus",
    "auditpol",
    "compname",
    "env",
    "filedialogmru",
    "gpo",
    "kb",
    "keyboard",
    "lastloggedon",
    "lastshutdown",
    "localgroups",
    "localusers",
    "mndmru",
    "mounteddevices",
    "mstscmru",
    "office_macros",
    "portproxy",
    "printer_history",
    "printer_ports",
    "proxy",
    "putty",
    "rdphint",
    "recentdocs",
    "regtime",
    "run",
    "runmru",
    "services",
    "shimcache",
    "srum",
    "sysinternals",
    "systeminfo",
    "tasks",
    "teamviewer",
    "timezone",
    "typedurls",
    "uninstall",
    "usbstor",
    "userassist",
    "usersids",
    "version",
    "wordwheelquery",
]


def test_bundled_plugin_inventory_and_imports() -> None:
    """The package contains and imports exactly the pinned 41 plugins."""
    discovered = sorted(
        module.name
        for module in pkgutil.iter_modules(plugins.__path__)
        if not module.ispkg and module.name != "base"
    )
    assert discovered == PLUGIN_NAMES

    for name in discovered:
        module = importlib.import_module(f"reg2es.plugins.{name}")
        assert module.Plugin.__module__ == module.__name__
