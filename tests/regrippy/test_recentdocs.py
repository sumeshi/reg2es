# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegBin

from reg2es.plugins.recentdocs import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    )
    reg = RegistryMock("NTUSER.DAT", "ntuser.dat", key.root())

    mrulistex = RegistryValueMock("MRUListEx", b"random bytes", RegBin)
    key.add_value(mrulistex)

    document = RegistryValueMock(
        "a",
        (
            b"m\x00y\x00d\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00"
            b".\x00d\x00o\x00c\x00x\x00\x00random_bytes\xca\xfe"
        ),
        RegBin,
    )
    key.add_value(document)
    japanese_document = RegistryValueMock(
        "b",
        "企画書.docx".encode("utf-16le") + b"\x00\x00random_bytes",
        RegBin,
    )
    key.add_value(japanese_document)

    return reg


def test_recentdocs(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "NTUSER.DAT", "-")

    results = list(p.run())

    assert [result.custom["docname"] for result in results] == [
        "mydocument.docx",
        "企画書.docx",
    ]
