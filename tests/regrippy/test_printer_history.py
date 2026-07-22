# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegDWord

from reg2es.plugins.printer_history import Plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock

PRINTERS = [
    "Microsoft Print To PDF",
    "Microsoft XPS Document Writer",
    "OneNote",
    "Fax",
    "Send To OneNote 2016",
    "MyEvilPrinter",
]


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build(r"Printers\ConvertUserDevModesCount")
    reg = RegistryMock("NTUSER.DAT", "ntuser.dat", key.root())

    for v in PRINTERS:
        val = RegistryValueMock(v, 0x00000001, RegDWord)
        key.add_value(val)

    return reg


def test_printer_history(mock_reg):
    p = Plugin(mock_reg, LoggerMock(), "NTUSER.DAT", "-")

    results = list(p.run())

    assert len(results) == len(PRINTERS), f"There should be {len(PRINTERS)} results"

    for r in results:
        assert r.value_name in PRINTERS, "The printer name should be valid"
