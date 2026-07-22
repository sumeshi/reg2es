# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.mndmru import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"
    )
    reg = RegistryMock("NTUSER.DAT", "ntuser.dat", key.root())

    mrulist = RegistryValueMock("MRUList", "ab", RegSZ)

    a = RegistryValueMock("a", "first", RegSZ)
    b = RegistryValueMock("b", "second", RegSZ)

    key.add_value(mrulist)
    key.add_value(b)
    key.add_value(a)

    return reg


def test_mndmru(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "NTUSER.DAT", "-")

    results = list(p.run())

    assert len(results) == 2, "There should be 2 results"
    assert results[0].value_data == "first", "First result should be 'a'"
    assert results[1].value_data == "second", "Second result should be 'b'"
