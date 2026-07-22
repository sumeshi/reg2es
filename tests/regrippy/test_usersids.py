# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.usersids import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build(
        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18"
    )
    reg = RegistryMock("SOFTWARE", "software", key.root())

    val = RegistryValueMock("ProfileImagePath", "systemprofile", RegSZ)
    key.add_value(val)

    return reg


def test_usersids(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "SOFTWARE", "-")

    results = list(p.run())
    assert len(results) == 1, "There should be a single result"
    assert (
        results[0].custom["value"] == "systemprofile:	S-1-5-18"
    ), "systemprofile:	S-1-5-18"
