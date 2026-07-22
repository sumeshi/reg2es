# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.timezone import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build("ControlSet001\\Control\\TimeZoneInformation")
    reg = RegistryMock("SYSTEM", "system", key.root())
    reg.set_ccs(1)

    val = RegistryValueMock("TimeZoneKeyName", "SampleTimezone", RegSZ)
    key.add_value(val)

    return reg


def test_timezone(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "SYSTEM", "-")

    results = list(p.run())

    assert len(results) == 1, "There should be a single result"
    assert (
        results[0].value_name == "TimeZoneKeyName"
    ), "It should have found the TimeZoneKeyName value"
    assert (
        results[0].value_data == "SampleTimezone"
    ), "It should have fetched the correct timezone value"
