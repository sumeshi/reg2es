# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.mstscmru import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build(r"Software\Microsoft\Terminal Server Client\Default")
    reg = RegistryMock("NTUSER.DAT", "ntuser.dat", key.root())

    mru0 = RegistryValueMock("MRU0", "127.0.0.1", RegSZ)
    mru1 = RegistryValueMock("MRU1", "10.0.0.1", RegSZ)

    key.add_value(mru0)
    key.add_value(mru1)

    return reg


def test_mndmru(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "NTUSER.DAT", "-")

    results = list(p.run())

    assert len(results) == 2, "There should be 2 results"
    assert results[0].value_data == "127.0.0.1", "First result should be '127.0.0.1'"
    assert results[1].value_data == "10.0.0.1", "Second result should be '10.0.0.1'"
