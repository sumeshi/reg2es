# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.keyboard import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build("Keyboard Layout")
    reg = RegistryMock("NTUSER.DAT", "ntuser.dat", key.root())

    preload = RegistryKeyMock("Preload", key)
    key.add_child(preload)

    substitutes = RegistryKeyMock("Substitutes", key)
    key.add_child(substitutes)

    french_layout_standard = RegistryValueMock("1", "0000040c", RegSZ)
    preload.add_value(french_layout_standard)

    french_canadian = RegistryValueMock("2", "d000040c", RegSZ)
    french_canadian_subs = RegistryValueMock("d000040c", "00001009", RegSZ)
    preload.add_value(french_canadian)
    substitutes.add_value(french_canadian_subs)

    return reg


def test_keyboard(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "NTUSER.DAT", "-")

    results = list(p.run())
    assert len(results) == 2, "There should be two results"
    assert any(
        [x.custom["substitute"] is not None for x in results]
    ), "One of the results should have a substitution"
    assert any(
        [x.custom["substitute"] is None for x in results]
    ), "One of the results should NOT have a substitution"
