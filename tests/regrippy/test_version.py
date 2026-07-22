# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegBin, RegSZ

from reg2es.plugins.version import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build("Microsoft\\Windows NT\\CurrentVersion")
    reg = RegistryMock("SOFTWARE", "software", key.root())

    name = RegistryValueMock("ProductName", "ENCOM OS-12", RegSZ)
    key.add_value(name)

    return reg


def test_version(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "SOFTWARE", "-")

    results = list(p.run())

    assert len(results) == 1, "There should be a single result"
    assert results[0].value_data == "ENCOM OS-12", "The retrieved version should match"
