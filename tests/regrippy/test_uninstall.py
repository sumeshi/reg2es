# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegSZ

from reg2es.plugins.uninstall import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build("Microsoft\\Windows\\CurrentVersion\\Uninstall")
    reg = RegistryMock("SOFTWARE", "software", key.root())

    word = RegistryKeyMock("winword", key)
    key.add_child(word)
    word_name = RegistryValueMock("DisplayName", "Microsoft Office Word", RegSZ)
    word_uninstall = RegistryValueMock(
        "UninstallString", "C:\\Program Files\\Word\\uninstall.exe", RegSZ
    )
    word.add_value(word_name)
    word.add_value(word_uninstall)

    mlwr = RegistryKeyMock("tasksche", key)
    key.add_child(mlwr)
    mlw_uninstall = RegistryValueMock(
        "UninstallString", "C:\\boguspath\\uninstall.exe", RegSZ
    )
    mlwr.add_value(mlw_uninstall)

    return reg


def test_uninstall(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "SOFTWARE", "-")

    results = list(p.run())

    assert len(results) == 2, "There should be 2 results"

    assert (
        results[0].key_name == "winword"
    ), "The first result keyname should be winword"
    assert (
        results[0].custom["display_name"] == "Microsoft Office Word"
    ), "The first result nice name should be Word"
    assert (
        results[0].custom["uninstall_string"]
        == "C:\\Program Files\\Word\\uninstall.exe"
    ), "The first result's uninstall path should match"

    assert (
        results[1].key_name == "tasksche"
    ), "The second result should be the bogus 'tasksche' entry"
    assert (
        results[1].custom["uninstall_string"] == "C:\\boguspath\\uninstall.exe"
    ), "The second entry's uninstall path should match"
