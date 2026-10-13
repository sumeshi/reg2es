# This file is derived from regrippy (https://github.com/airbus-cert/regrippy)
# commit 32e3ab3243415b7bf46f812d933f4d29862e3046 (v2.0.3), licensed under Apache-2.0.
# Modifications: import path changed from 'regrippy' to 'reg2es.plugins'.

import pytest
from Registry.Registry import RegDWord, RegSZ
from unittest.mock import Mock

from reg2es.plugins.services import Plugin as plugin

from .reg_mock import LoggerMock, RegistryKeyMock, RegistryMock, RegistryValueMock


@pytest.fixture
def mock_reg():
    key = RegistryKeyMock.build("ControlSet002\\Services")
    reg = RegistryMock("SYSTEM", "system", key.root())
    reg.set_ccs(2)

    srv1 = RegistryKeyMock("Service1", key)
    key.add_child(srv1)
    srv1_image = RegistryValueMock(
        "ImagePath", "C:\\windows\\system32\\srv1.sys", RegSZ
    )
    srv1.add_value(srv1_image)

    srv2 = RegistryKeyMock("Service2", key)
    key.add_child(srv2)

    return reg


def test_services(mock_reg):
    p = plugin(mock_reg, LoggerMock(), "SYSTEM", "-")

    results = list(p.run())

    assert len(results) == 2, "There should be two results"

    assert (
        results[0].key_name == "Service1"
    ), "The first service should be named 'Service1'"
    assert (
        results[0].custom["image_path"] == "C:\\windows\\system32\\srv1.sys"
    ), "The first service's image path should match"

    assert (
        results[1].key_name == "Service2"
    ), "The second service should be named 'Service2'"


@pytest.mark.parametrize("value_name", ["ImagePath", "Start", "Description", "ObjectName"])
def test_malformed_service_does_not_stop_later_services(mock_reg, value_name):
    services = mock_reg.open("ControlSet002\\Services")
    malformed = RegistryKeyMock("MalformedService", services)
    value = RegistryValueMock(value_name, "", RegSZ)
    value.value = Mock(side_effect=ValueError("corrupt value"))
    malformed.add_value(value)
    services._subkeys.insert(1, malformed)
    logger = Mock()

    instance = plugin(mock_reg, logger, "SYSTEM", "/case/SYSTEM")
    results = list(instance.run())

    assert [result.key_name for result in results] == ["Service1", "Service2"]
    logger.warning.assert_called_once()
    warning = logger.warning.call_args.args[0]
    assert "MalformedService" in warning
    assert "/case/SYSTEM" in warning
    assert instance.errors == [{
        "plugin": "services", "hive": "SYSTEM", "hive_path": "/case/SYSTEM",
        "key": malformed.path(), "value": value_name,
        "error": "ValueError: corrupt value",
    }]


def test_unknown_start_mode_is_retained(mock_reg):
    from reg2es.models.Reg2es import plugin_result_to_document
    from reg2es.plugins.services import ServiceStartMode

    service = mock_reg.open("ControlSet002\\Services").subkeys()[0]
    service.add_value(RegistryValueMock("Start", 99, RegDWord))
    instance = plugin(mock_reg, Mock(), "SYSTEM", "/case/SYSTEM")
    instance.error_policy = "raise"
    results = list(instance.run())

    assert len(results) == 2
    assert results[0].custom["start_mode"] == ServiceStartMode.UNKNOWN
    assert results[0].custom["start_mode_raw"] == 99
    assert instance.errors == []
    doc = plugin_result_to_document(results[0], "services", "SYSTEM", "/case/SYSTEM")
    assert doc["reg2es"]["custom"]["start_mode"] == -1
    assert doc["reg2es"]["custom"]["start_mode_raw"] == 99
